FROM behaviorlock-runner:dev

ARG BEHAVIORLOCK_CONTROL_MODE
ENV BEHAVIORLOCK_CONTROL_MODE=$BEHAVIORLOCK_CONTROL_MODE
COPY --chmod=0555 controlled-entrypoint.sh /opt/behaviorlock/controlled-entrypoint.sh
ENTRYPOINT ["/opt/behaviorlock/controlled-entrypoint.sh"]
