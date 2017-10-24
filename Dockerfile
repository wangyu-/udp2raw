FROM alpine:3.6 as builder

WORKDIR /

RUN apk add --no-cache git  build-base linux-headers && \
 git clone https://github.com/wangyu-/udp2raw-tunnel.git  && \
 cd udp2raw-tunnel && \
 make dynamic

FROM alpine:3.6
RUN apk add --no-cache libstdc++ iptables
COPY --from=builder /udp2raw-tunnel/udp2raw_dynamic /bin/
ENTRYPOINT [ "/bin/udp2raw_dynamic" ]
