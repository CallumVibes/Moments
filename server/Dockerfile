# Moments OPRF server. No dependencies, no build step — the curve code is
# generated into server/ by the app's own `npm run build`.
#
# Build from the REPOSITORY ROOT so vendor-secp256k1.mjs is in context:
#   docker build -f server/Dockerfile -t moments-oprf .
FROM node:22-alpine

# Runs unprivileged: this process holds a secret that must never be recoverable
# from a compromised container.
RUN addgroup -S oprf && adduser -S oprf -G oprf
WORKDIR /app

COPY server/oprf-server.mjs server/vendor-secp256k1.mjs ./server/

USER oprf
ENV PORT=8787
EXPOSE 8787

# No shell wrapper, so signals reach node directly and the container stops
# cleanly instead of being killed after a timeout.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "server/oprf-server.mjs"]
