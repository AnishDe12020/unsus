#!/usr/bin/env bash

unsus_require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 127
  fi
}

unsus_gcloud_project() {
  local project="${UNSUS_GCLOUD_PROJECT:-}"
  if [[ -z "${project}" ]]; then
    project="$(gcloud config get-value project 2>/dev/null || true)"
  fi
  if [[ -z "${project}" || "${project}" == "(unset)" ]]; then
    echo "Set UNSUS_GCLOUD_PROJECT or configure gcloud core/project." >&2
    exit 2
  fi
  printf '%s\n' "${project}"
}

unsus_gcloud_zone() {
  local zone="${UNSUS_GCLOUD_ZONE:-}"
  if [[ -z "${zone}" ]]; then
    zone="$(gcloud config get-value compute/zone 2>/dev/null || true)"
  fi
  if [[ -z "${zone}" || "${zone}" == "(unset)" ]]; then
    zone="us-central1-a"
  fi
  printf '%s\n' "${zone}"
}
