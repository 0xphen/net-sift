pub trait Parser {
    fn parse_next_layer(&self) -> Option<Box<dyn Parser>>;
}
