# DHC3PO

## Requirements

Just rust! No dependencies

## Install

`git clone https://github.com/acottis/dhc3po.git`

`cd dhc3po`

`cargo install --path . --root $HOME/.cargo && sudo setcap 'cap_net_bind_service=+ep' $HOME/.cargo/bin/dhc3po`

## Usage

To run the server just `cargo run --release`. On Linux will need to either run as sudo 
or see [Development](#Development)

## Future

* Investigate switching to RwLock from Mutex
* Web GUI that can read the state
* Pass config in without recompile

## Development

Useful command for running on a low port in linux

`cargo watch -x 'build && sudo setcap 'cap_net_bind_service=+ep' target/debug/dhc3po && cargo r'`

`cargo watch` for the auto restart on saving files

`setcap 'cap_net_bind_service=+ep'` allows us to bind to a low port without root
