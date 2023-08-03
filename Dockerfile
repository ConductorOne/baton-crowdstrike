FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-crowdstrike"]
COPY baton-crowdstrike /