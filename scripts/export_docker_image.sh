#!/usr/bin/env bash
set -euo pipefail

# Export a ready-to-use PyGuard Docker image as a compressed tarball
# Usage: ./scripts/export_docker_image.sh [image[:tag]] [output_prefix]
# Defaults: image=pyguard:latest, output_prefix derived from tag and date

IMAGE_NAME="${1:-pyguard:latest}"
TAG_PART="${IMAGE_NAME#*:}"
DATE_PART="$(date +%Y%m%d)"
OUT_PREFIX="${2:-pyguard-${TAG_PART}-${DATE_PART}}"

OUT_TAR="${OUT_PREFIX}.tar"
OUT_TGZ="${OUT_TAR}.gz"
OUT_SHA="${OUT_TGZ}.sha256"

echo "[export] Inspecting image: ${IMAGE_NAME}"
docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1 || {
  echo "[export] ERROR: Image '${IMAGE_NAME}' not found. Build it first, e.g.:" >&2
  echo "[export]   docker build -t pyguard:latest -f docker/Dockerfile.wg-go ." >&2
  exit 1
}

echo "[export] Saving image -> ${OUT_TAR} (then compressing)"
rm -f -- "${OUT_TAR}" "${OUT_TGZ}" "${OUT_SHA}" || true
docker save "${IMAGE_NAME}" -o "${OUT_TAR}"

echo "[export] Compressing ${OUT_TAR} -> ${OUT_TGZ}"
gzip -9 "${OUT_TAR}"

echo "[export] Computing checksum -> ${OUT_SHA}"
sha256sum "${OUT_TGZ}" > "${OUT_SHA}"

SIZE=$(du -h "${OUT_TGZ}" | awk '{print $1}')
echo "[export] Done. Created ${OUT_TGZ} (${SIZE}) and checksum ${OUT_SHA}"

cat <<'EOF'

How to use on another host (no repo required):

1) Copy the archive to the target machine and verify checksum (optional):
   sha256sum -c <file>.sha256

2) Load the image into Docker:
   docker load -i <file>.tar.gz

3) Run PyGuard (example):
   docker run -d \
     --name pyguard \
     --cap-add NET_ADMIN \
     --device /dev/net/tun \
     -p 6656:6656/tcp \
     -p 51820:51820/udp \
     -p 53:53/udp \
     -e PYGUARD_AUTOCREATE=1 \
     -v pyguard-data:/etc/pyguard \
     -v wireguard-data:/etc/wireguard \
     -v pyguard-logs:/var/log/pyguard \
     pyguard:latest

   Notes:
   - Adjust the UDP WireGuard port mapping (51820) if you configure a different port later in the UI.
   - First login default username is 'admin'. Change the password immediately in Settings.
   - If running on ARM hosts, build a matching image for that architecture.

4) Open the web UI at http://<HOST-IP>:6656

EOF
