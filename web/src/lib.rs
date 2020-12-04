#![feature(never_type)]
#![recursion_limit="512"]


// Use `wee_alloc` as the global allocator.
//#[global_allocator]
//static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew_router::prelude::*;

mod account_creation;

#[derive(Switch, Debug, Clone)]
pub enum AppRoute {
    #[to = "/signup"]
    SignUp,
    #[to = "/"]
    Index,
}

type AppRouter = Router<AppRoute>;
type AppAnchor = RouterAnchor<AppRoute>;


struct Question {
    link: ComponentLink<Self>,
    text: String,
}

enum Msg {
    Update(String),
}

impl Component for Question {
    type Message = Msg;
    type Properties = ();
    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        Self {
            link,
            text: "hey".to_string(),
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            Msg::Update(text) => {
                self.text = text;
            }
        }
        true
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        // Should only return "true" if new properties are different to
        // previously received properties.
        // This component has no properties so we will always return "false".
        false
    }

    fn view(&self) -> Html {
        html!{
            <AppRouter
                render = Router::render(|switch: AppRoute| {
                    match switch {
                        AppRoute::SignUp => html!{<account_creation::Model/>},
                        AppRoute::Index => html!{
                            <AppAnchor route=AppRoute::SignUp>
                                { "SignUp" }
                            </AppAnchor>},
                    }
                })
            />
        }
    }

    /*
    fn view(&self) -> Html {
        use account_creation::Model;
        html!{
            <Router<AppRoute, ()>
                render = Router::render(|switch: AppRoute| {
                    match switch {
                        AppRoute::SignUp => html!{<Model/>},
                        AppRoute::Index => html!{<>
                            <input
                                class="edit"
                                type="text"
                                value=&self.text
                                oninput=self.link.callback(|e: InputData| Msg::Update(e.value))
                            />
                            <div class="grid-container">
                                <div class="item1">{&self.text}</div>
                                <div class="item2">{"Menu"}</div>
                                <div class="item3">{"Main"}</div>  
                                <div class="item4">{"Right"}</div>
                                <div class="item5">{"Footer"}</div> 
                                
                            </div>
                            <>
                            {for (0..self.text.len()).map(|i| html!{<div>{i}</div>} )}
                            </>
                        </>},
                    }
                })
            />
        }

    }
    */
}


#[wasm_bindgen(start)]
pub fn run_app() {
    wasm_logger::init(wasm_logger::Config::default());
    App::<Question>::new().mount_to_body();
    //App::<account_creation::Model>::new().mount_as_body();
}
