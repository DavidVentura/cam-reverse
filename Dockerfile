FROM node:lts-alpine AS build

ADD . /app

WORKDIR /app

RUN npm install && npm run build

FROM node:lts-alpine

COPY --from=build /app/dist/bin.cjs /cam-reverse.cjs

ENTRYPOINT ["node", "/cam-reverse.cjs"]
