use proveno::policy::profiles::template_price_feed_v1;

fn main() {
    let hash = template_price_feed_v1().policy_hash();
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
