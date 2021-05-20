fn main()
{
  // let ver = gcrypt::check_version(None).unwrap();
  // println!("version: {}", ver);
  // Control::disable_secure_memory().unwrap();
  // Control::initialization_finished().unwrap();

  println!("Md");

  for md_algo in gcrypt::md::Algorithm::ALGORITHMS {
    println!("{:?}", md_algo);
  }

  println!("Mac");

  for mac_algo in gcrypt::mac::Algorithm::ALGORITHMS {
    println!("{:?}", mac_algo);
  }
}
