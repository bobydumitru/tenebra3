#![cfg_attr(target_arch = "bpf", no_std)]

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

const MAGIC: &[u8; 8] = b"TNB-SOL1";
const STATE_HEADER: usize = 8 + 32 + 32 + 8;
const DEPOSIT_ID_SIZE: usize = 32;
const MAX_DEPOSITS: usize = 4096;
const STATE_SIZE: usize = STATE_HEADER + MAX_DEPOSITS * DEPOSIT_ID_SIZE;

#[derive(Clone, Copy)]
enum Instruction {
    Initialize { authority: Pubkey, vault: Pubkey },
    Deposit { amount: u64, deposit_id: [u8; 32], recipient: [u8; 32] },
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    let end = offset.checked_add(8).ok_or(ProgramError::InvalidInstructionData)?;
    data.get(offset..end)
        .ok_or(ProgramError::InvalidInstructionData)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn decode_instruction(data: &[u8]) -> Result<Instruction, ProgramError> {
    match data.first().copied() {
        Some(0) if data.len() == 1 + 32 + 32 => {
            Ok(Instruction::Initialize {
                authority: Pubkey::new_from_array(data[1..33].try_into().unwrap()),
                vault: Pubkey::new_from_array(data[33..65].try_into().unwrap()),
            })
        }
        Some(1) if data.len() == 1 + 8 + 32 + 32 => Ok(Instruction::Deposit {
            amount: u64::from_le_bytes(data[1..9].try_into().unwrap()),
            deposit_id: data[9..41].try_into().unwrap(),
            recipient: data[41..73].try_into().unwrap(),
        }),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
    match decode_instruction(input)? {
        Instruction::Initialize { authority, vault } => {
            let accounts = &mut accounts.iter();
            let payer = next_account_info(accounts)?;
            let state = next_account_info(accounts)?;
            let system = next_account_info(accounts)?;
            if !payer.is_signer || !system.executable {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let (expected_state, bump) = Pubkey::find_program_address(&[b"vault", authority.as_ref()], program_id);
            if expected_state != *state.key || vault == Pubkey::default() {
                return Err(ProgramError::InvalidSeeds);
            }
            let space = STATE_SIZE;
            let rent = Rent::get()?.minimum_balance(space);
            invoke_signed(
                &system_instruction::create_account(payer.key, state.key, rent, space as u64, program_id),
                &[payer.clone(), state.clone(), system.clone()],
                &[&[b"vault", authority.as_ref(), &[bump]]],
            )?;
            let mut data = state.try_borrow_mut_data()?;
            data[..8].copy_from_slice(MAGIC);
            data[8..40].copy_from_slice(authority.as_ref());
            data[40..72].copy_from_slice(vault.as_ref());
            data[72..80].copy_from_slice(&0u64.to_le_bytes());
            Ok(())
        }
        Instruction::Deposit { amount, deposit_id, recipient: _ } => {
            if amount == 0 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let accounts = &mut accounts.iter();
            let depositor = next_account_info(accounts)?;
            let state = next_account_info(accounts)?;
            let vault = next_account_info(accounts)?;
            let system = next_account_info(accounts)?;
            if !depositor.is_signer || !depositor.is_writable || !state.is_writable || !vault.is_writable || !system.executable {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let mut data = state.try_borrow_mut_data()?;
            if data.len() < STATE_HEADER || &data[..8] != MAGIC || Pubkey::new_from_array(data[40..72].try_into().unwrap()) != *vault.key {
                return Err(ProgramError::InvalidAccountData);
            }
            let count = read_u64(&data, 72)? as usize;
            let required = STATE_HEADER.checked_add((count + 1).checked_mul(DEPOSIT_ID_SIZE).ok_or(ProgramError::AccountDataTooSmall)?).ok_or(ProgramError::AccountDataTooSmall)?;
            if count >= MAX_DEPOSITS || required > data.len() {
                return Err(ProgramError::AccountDataTooSmall);
            }
            let ids_start = STATE_HEADER;
            for existing in data[ids_start..ids_start + count * DEPOSIT_ID_SIZE].chunks_exact(DEPOSIT_ID_SIZE) {
                if existing == deposit_id {
                    return Err(ProgramError::AccountAlreadyInitialized);
                }
            }
            invoke(&system_instruction::transfer(depositor.key, vault.key, amount), &[depositor.clone(), vault.clone(), system.clone()])?;
            let start = ids_start + count * DEPOSIT_ID_SIZE;
            data[start..start + DEPOSIT_ID_SIZE].copy_from_slice(&deposit_id);
            data[72..80].copy_from_slice(&((count as u64) + 1).to_le_bytes());
            Ok(())
        }
    }
}

entrypoint!(process_instruction_entry);
fn process_instruction_entry(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
    process_instruction(program_id, accounts, input)
}
