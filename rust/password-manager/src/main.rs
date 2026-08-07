use rand::Rng;
use std::io;
m
fn read_integer() -> i32 {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    input
        .trim()
        .parse::<i32>()
        .expect("Please enter a valid integer")
}
fn main() {
    let number: i32 = rand::thread_rng().gen_range(1..=100);
    let mut tries = 0;
    while tries < 3 {
        println!("Enter your guess: ");
        let guess = read_integer();

        tries = tries + 1;

        if guess == number {
            println!("You guessed the number");
            break;
        } else if guess < number {
            println!("number is higher");
        } else if guess > number {
            println!("number is lower");
        } else {
            println!("You got it wrong bum");
        }
    }
}
