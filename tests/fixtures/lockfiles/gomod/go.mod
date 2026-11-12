module example.com/canary

go 1.21

require (
	golang.org/x/text v0.3.7
	github.com/stretchr/testify v1.8.4 // indirect
	example.com/local v0.0.0
)

require golang.org/x/net v0.7.0

replace example.com/local => ../local
