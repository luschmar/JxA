FROM node:22.15

RUN npm install pm2 -g
COPY ../../fxa /app

# Initialize the L10n repository
RUN /app/_scripts/l10n/clone.sh && yarn install

EXPOSE 3000


WORKDIR /app/packages/fxa-settings

CMD [ "pm2-runtime", "start", "pm2.config.js" ]
