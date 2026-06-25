# Specifies the type of version bump to apply. Change this value as needed before releasing.
# Accepted values:
# major - e.g 1.0.0 -> 2.0.0
# minor - e.g 1.0.0 -> 1.1.0
# patch - e.g 1.0.0 -> 1.0.1
RELEASE_TYPE := patch
CURRENT_VERSION := $(shell git ls-remote -q --tags --sort=-v:refname | sed -n '1p; 1q' | awk '{ print $$2 }' | sed 's/refs\/tags\///g')
NEXT_VERSION := $(shell semver -c -i $(RELEASE_TYPE) $(CURRENT_VERSION))

current-version:
	@echo $(CURRENT_VERSION)

next-version:
	@echo $(NEXT_VERSION)

release:
	git tag v$(NEXT_VERSION)
	git push origin v$(NEXT_VERSION)
