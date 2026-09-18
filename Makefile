ARCH := x86_64
NAME := cflinuxfs5
BASE := ubuntu:noble
BUILD := $(NAME).$(ARCH)
FIPS_BUILD := $(NAME)-fips.$(ARCH)

all: $(BUILD).tar.gz

# FIPS variant. Requires a Ubuntu Pro token with the fips-updates entitlement
# in UA_TOKEN (guest tokens are single-use; one token builds one image):
#   make fips UA_TOKEN="$$(sudo pro api u.pro.attach.guest.get_guest_token.v1 | jq -r .data.attributes.guest_token)"
fips: $(FIPS_BUILD).tar.gz

$(BUILD).iid:
	docker build \
	--build-arg "base=$(BASE)" \
	--build-arg packages="`cat "packages/$(NAME)" 2>/dev/null`" \
	--build-arg locales="`cat locales`" \
	--no-cache "--iidfile=$(BUILD).iid" .


$(BUILD).tar.gz: $(BUILD).iid
	docker run "--cidfile=$(BUILD).cid" `cat "$(BUILD).iid"` dpkg -l | tee "packages-list"
	docker export `cat "$(BUILD).cid"` | gzip > "$(BUILD).tar.gz"
	echo "Rootfs SHASUM: `shasum -a 256 "$(BUILD).tar.gz" | cut -d' ' -f1`" > "receipt.$(BUILD)"
	echo "" >> "receipt.$(BUILD)"
	cat "packages-list" >> "receipt.$(BUILD)"
	docker rm -f `cat "$(BUILD).cid"`
	rm -f "$(BUILD).cid" "packages-list"

$(FIPS_BUILD).iid:
	docker build \
	--build-arg "base=$(BASE)" \
	--build-arg packages="`cat "packages/$(NAME)" 2>/dev/null`" \
	--build-arg locales="`cat locales`" \
	--secret "id=ua_token,env=UA_TOKEN" \
	--no-cache "--iidfile=$(FIPS_BUILD).iid" \
	-f Dockerfile.fips .

$(FIPS_BUILD).tar.gz: $(FIPS_BUILD).iid
	docker run "--cidfile=$(FIPS_BUILD).cid" `cat "$(FIPS_BUILD).iid"` dpkg -l | tee "packages-list"
	docker export `cat "$(FIPS_BUILD).cid"` | gzip > "$(FIPS_BUILD).tar.gz"
	echo "Rootfs SHASUM: `shasum -a 256 "$(FIPS_BUILD).tar.gz" | cut -d' ' -f1`" > "receipt.$(FIPS_BUILD)"
	echo "" >> "receipt.$(FIPS_BUILD)"
	cat "packages-list" >> "receipt.$(FIPS_BUILD)"
	docker rm -f `cat "$(FIPS_BUILD).cid"`
	rm -f "$(FIPS_BUILD).cid" "packages-list"
