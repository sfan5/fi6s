FROM alpine:edge
LABEL repository "https://github.com/sfan5/fi6s"

RUN apk --update \
        --no-cache \
        --virtual .deps add build-base \
                            linux-headers \
                            git \
  && apk --no-cache --update add libcap \
                                 libpcap-dev \
  && git clone --branch=master \
               --depth=1 \
               https://github.com/sfan5/fi6s.git \
  && cd fi6s \
  && make BUILD_TYPE=release \
  && make install \
  && rm -rf /fi6s \
  && apk del .deps

RUN adduser -D scan \
  && setcap cap_net_raw=eip /usr/bin/fi6s

USER scan

ENTRYPOINT ["fi6s"]
