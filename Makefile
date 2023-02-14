GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

# remove debugging symbols
LDFLAGS += -s -w

PLATFORM := $(shell uname -s)

.PHONY: age age-yubikeygen age-keygen

all: age age-yubikeygen age-keygen

age:
	@echo ">  Building age command..." 
	@$(GOBUILD) -ldflags="${LDFLAGS}" ./cmd/age 

age-keygen:
	@echo ">  Building age-keygen command..." 
	@$(GOBUILD) -ldflags="${LDFLAGS}" ./cmd/age-keygen

age-yubikeygen:
	@echo ">  Building age-yubikeygen command..." 
	@$(GOBUILD) -ldflags="${LDFLAGS}" ./cmd/age-yubikeygen

test:
	@$(GOTEST) .

clean: 
	$(GOCLEAN)
	rm -f age
	rm -f age-yubikeygen
	rm -f age-keygen