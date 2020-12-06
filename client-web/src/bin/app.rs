use client_web::Question;

fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    yew::start_app::<client_web::Question>();
}
