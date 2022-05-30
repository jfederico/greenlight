FROM alpine:3.16 AS alpine

ARG RAILS_ROOT=/usr/src/app
ENV RAILS_ROOT=${RAILS_ROOT}

FROM alpine AS base
WORKDIR $RAILS_ROOT
RUN apk add --no-cache \
    libpq \
    libxml2 \
    libxslt \
    ruby \
    ruby-irb \
    ruby-bigdecimal \
    ruby-bundler \
    ruby-json \
    tzdata \
    bash \
    shared-mime-info

FROM base
RUN apk add --no-cache \
    build-base \
    curl-dev \
    git \
    libxml2-dev \
    libxslt-dev \
    pkgconf \
    postgresql-dev \
    sqlite-libs \
    sqlite-dev \
    ruby-dev \
    nodejs \
    yarn \
    yaml-dev \
    zlib-dev \
    && ( echo 'install: --no-document' ; echo 'update: --no-document' ) >>/etc/gemrc
COPY Gemfile* ./
RUN bundle install \
    && yarn install
#    && rm -rf vendor/bundle/ruby/*/cache \
#    && find vendor/bundle/ruby/*/gems/ \( -name '*.c' -o -name '*.o' \) -delete
#RUN gem install bundler
#RUN bundle config build.nokogiri --use-system-libraries \
#    && bundle config set --local deployment 'true'  without 'development:test' \
#    && bundle install -j4 \
#    && yarn install
#    && rm -rf vendor/bundle/ruby/*/cache \
#    && find vendor/bundle/ruby/*/gems/ \( -name '*.c' -o -name '*.o' \) -delete
COPY . ./
#USER greenlight:greenlight

ARG RAILS_ENV
ENV RAILS_ENV=${RAILS_ENV:-production}
ARG RAILS_LOG_TO_STDOUT
ENV RAILS_LOG_TO_STDOUT=${RAILS_LOG_TO_STDOUT:-true}

ARG VERSION_CODE
ENV VERSION_CODE=$VERSION_CODE

EXPOSE 3000

ENTRYPOINT [ "./bin/start" ]
