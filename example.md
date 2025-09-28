gen : cargo run -- gen

sign : cargo run -- sign-from-request LIC-2025 <Your key> > license.json
