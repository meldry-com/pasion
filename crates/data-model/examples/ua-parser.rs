use pasion_data_model::UserAgent;

/// Simple command-line tool to try out user-agent parsing
///
/// It parses user-agents from stdin and prints the parsed user-agent to stdout.
fn main() {
    for line in std::io::stdin().lines() {
        let user_agent = line.unwrap();
        let user_agent = UserAgent::parse(user_agent);
        println!("{user_agent:?}");
    }
}
