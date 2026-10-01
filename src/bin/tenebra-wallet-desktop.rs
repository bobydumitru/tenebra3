//! TENEBRA Wallet desktop preview. No keys, passwords, balances, or transactions are handled here.

use eframe::egui;

struct TenebraWallet;

impl eframe::App for TenebraWallet {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(egui::Color32::from_rgb(12, 12, 15)))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(
                        egui::RichText::new("TSC-1 NETWORK  ·  PREVIEW")
                            .color(egui::Color32::from_rgb(210, 177, 104)),
                    );
                    ui.add_space(12.0);
                    ui.add(
                        egui::Image::new(egui::include_image!("../../assets/tnb-emblem-v2.png"))
                            .fit_to_exact_size(egui::vec2(220.0, 220.0)),
                    );
                    ui.heading(
                        egui::RichText::new("TENEBRA Wallet")
                            .color(egui::Color32::from_rgb(246, 233, 207)),
                    );
                    ui.label("TNB  ·  Private by design");
                    ui.add_space(24.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(360.0);
                        ui.label("TNB BALANCE");
                        ui.heading("Unavailable");
                        ui.label("No active network is connected.");
                    });
                    ui.add_space(10.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(360.0);
                        ui.label("WALLET ADDRESS");
                        ui.label("Secure local wallet connection is not available yet.");
                    });
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        ui.add_enabled(false, egui::Button::new("Send TNB"));
                        ui.add_enabled(false, egui::Button::new("Mine TNB"));
                    });
                    ui.add_space(16.0);
                    ui.small("Preview only. Do not use with real funds.");
                });
            });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([490.0, 660.0]),
        ..Default::default()
    };
    eframe::run_native(
        "TENEBRA Wallet",
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            Ok(Box::new(TenebraWallet))
        }),
    )
}
