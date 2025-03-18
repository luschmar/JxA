package ch.luschmar.jxa.auth.server.api.account.create;

public record MetricsContent(String deviceId, String entrypoint, String entrypointExperiment,
                             String entrypointVariation, String flowId, String flowBeginTime, String utmCampaign,
                             String utmContent, String utmMedium, String utmSource, String utmTerm, String productId,
                             String planId) {
}
