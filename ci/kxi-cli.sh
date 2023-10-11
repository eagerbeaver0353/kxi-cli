#!/bin/bash
set -e

# This script is used to centralize all the different CI scripts through a command line.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
CI_SCRIPTS_ROOT_DIR="${CI_SCRIPTS_ROOT_DIR:=${DIR}/../ci-scripts/src}"
if [[ -n "${CI:=}" ]]; then
    CI_SCRIPTS_ROOT_DIR="/ci-scripts/"
fi
for library in common/git common/log ci/release; do
    source_path="${CI_SCRIPTS_ROOT_DIR}/${library}.sh"
    if [[ -f "${source_path}" ]]; then
        # shellcheck source=/dev/null
        source "${CI_SCRIPTS_ROOT_DIR}/${library}.sh"
    else
        echo "[WARNING] ${source_path} does not exist."
    fi
done

SETUP_LOCAL_CI=false
AUTO_TAG_BRANCH=false
AUTO_APPROVE_MR=false
GITLAB_TOKEN="${GITLAB_TOKEN:=}"

help() {
    cat <<EOF
Run a CI command with this script.

Usage: kxi-cli.sh [OPTIONS]

Options:
    -h|--help                            This message.
    -s|--setup-local-ci                  Setup local ci-scripts.
    -m|--auto-approve-mr                 Auto approve the current MR.
    -a|--auto-tag-release-branch         Auto tag the current branch if it's a release branch.
EOF
}

setup_local_ci() {
    if [[ ! -d "ci-scripts/" ]]; then
        git clone git@gitlab.com:kxdev/kxinsights/k8s-infrastructure/ci-scripts.git
    fi
}

auto_approve_mr() {
    approve_mr "${CI_MERGE_REQUEST_IID}"
}

auto_tag() {
    local bumped_tag=""
    local tag_msg=""

    bumped_tag=$(auto_tag_release_branch "${CI_PROJECT_ID}" "${GITLAB_TOKEN}" "${CI_COMMIT_BRANCH}")
    tag_msg="Auto tag - Bumped tag to ${bumped_tag}"
    gitlab_create_tag "${CI_PROJECT_ID}" "${GITLAB_TOKEN}" "${bumped_tag}" "${CI_COMMIT_BRANCH}" "${tag_msg}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
    -a | --auto-tag-release-branch)
        AUTO_TAG_BRANCH=true
        ;;
    -m | --auto-approve-mr)
        AUTO_APPROVE_MR=true
        ;;
    -s | --setup-local-ci)
        SETUP_LOCAL_CI=true
        ;;
    --help | -h)
        help
        exit 0
        ;;
    *)
        log Unknown flag "$1"
        help
        exit 1
        ;;
    esac
    shift
done

if [[ "${SETUP_LOCAL_CI}" == true ]]; then
    setup_local_ci
fi

if [[ "${AUTO_APPROVE_MR}" == true ]]; then
    auto_approve_mr
fi

if [[ "${AUTO_TAG_BRANCH}" == true ]]; then
    auto_tag
fi
