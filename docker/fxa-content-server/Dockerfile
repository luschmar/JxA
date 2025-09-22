FROM node:22.15

COPY ../../fxa /app

# Initialize the L10n repository
RUN /app/_scripts/l10n/clone.sh && yarn install

RUN cat /app/packages/fxa-content-server/server/config/fxaci.json | sed -e 's/https:\/\/fxaci\.dev\.lcip\.org\/auth/http:\/\/localhost:8080/' > /app/packages/fxa-content-server/server/config/fxaci.json

RUN yarn install

EXPOSE 3030

WORKDIR /app/packages/fxa-content-server

CMD ["yarn","start-remote"]