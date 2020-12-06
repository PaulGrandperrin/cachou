use client_web::Question;

cfg_if::cfg_if! {
    if #[cfg(feature = "logging")] {
        fn init_log() {
            //use log::Level;
            //console_log::init_with_level(Level::Trace).expect("error initializing log");
            tracing_wasm::set_as_global_default();
        }
    } else {
        fn init_log() {}
    }
}

fn main() {
    init_log();
    yew::start_app::<client_web::Question>();
}
