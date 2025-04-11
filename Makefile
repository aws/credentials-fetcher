BIN_DIR=${BGO_BUILD_ROOT}/bin
TMP_DIR=${BGO_BUILD_ROOT}/private/tmp/lambdabuild

# Run the strict release to allow vetting and race detection.
BGO_RELEASE_TARGET=release-strict

# Apply some flags to strip resulting executable & make it static:
# -trimpath removes all file system paths
# -buildvcs=0 omits version control info
# -dwarf=0 -s -w strip out debug info
# -buildid= omits build id
# -tags netgo builds a pure Go net package
# -tags osusergo builds a pure Go user package
# -tags lambda.norpc drops RPC dependencies
GO_INSTALL_FLAGS:=-trimpath -buildvcs=0 -gcflags "-dwarf=0 -buildid=" \
	-ldflags "-s -w -buildid=" -tags osusergo,netgo,lambda.norpc

# Defines a bunch of standard build targets.
# For more info see: https://code.amazon.com/packages/BrazilMakeGo/blobs/mainline/--/configuration/bin/bgo.makefile
include ${BGO_MAKEFILE}

# Extend the release process to run security and linting before we construct the lambda zips.
release-strict:: security-check lint-check build-for-lambda

.PHONY: security-check
security-check::
	mkdir -p build/private/gosec
	gosec -fmt=json -out=build/private/gosec/results.json ./... || (cat build/private/gosec/results.json ; echo; echo "GoSec returned with error. Fix the errors above or add the comment '/* #nosec */' to ignore the affected line."; exit 1)

.PHONY: lint-check
lint-check::
	golangci-lint run ./...

# Build binaries for linux so they work with Lambda and then package
# up each binary into a separate zip file for deployment.
# The binary is renamed to 'bootstrap' as required by the al2 runtime.
.PHONY: build-for-lambda
build-for-lambda:
	env GOOS=linux GOARCH=amd64 go build -o ${BIN_DIR} $(GO_INSTALL_FLAGS) $V $T
	mkdir -p $(TMP_DIR)
	for f in $(BIN_DIR)/lambda*; do\
		cp $${f} $(TMP_DIR)/bootstrap;\
		echo zipping $${f}.zip;\
		zip --must-match -j9 $${f}.zip $(TMP_DIR)/bootstrap;\
		rm $(TMP_DIR)/bootstrap;\
	done
	mv $(BIN_DIR)/lambda*.zip $(BGO_BUILD_ROOT)
