# dhc3po

## Development

Useful command for running on a low port in linux
`cargo watch -x 'build && sudo setcap 'cap_net_bind_service=+ep' target/debug/dhc3po && cargo r'`
