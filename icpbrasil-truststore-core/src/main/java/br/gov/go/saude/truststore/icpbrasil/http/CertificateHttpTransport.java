package br.gov.go.saude.truststore.icpbrasil.http;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodySubscriber;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow.Subscription;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Transporte HTTP para extensoes X.509, sem redirects e com limite durante o recebimento.
 * O cliente injetado pertence ao chamador e nao e fechado por este transporte.
 */
public final class CertificateHttpTransport {

    private final HttpClient client;
    private final DownloadPolicy policy;

    /**
     * @param client cliente confiavel, obrigatoriamente com {@link HttpClient.Redirect#NEVER}
     * @param policy politica aplicada antes de cada tentativa HTTP
     * @throws IllegalArgumentException se o cliente permitir redirects automaticos
     */
    public CertificateHttpTransport(HttpClient client, DownloadPolicy policy) {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("Downloads de certificados exigem Redirect.NEVER");
        }
        this.client = client;
        this.policy = Objects.requireNonNull(policy);
    }

    /**
     * Recebe apenas HTTP 200. Limita todos os corpos, inclusive erros HTTP e respostas chunked.
     * O timeout obrigatorio da requisicao cobre toda a troca HTTP, incluindo o corpo;
     * cada retry inicia um novo prazo. A resolucao DNS da politica depende do resolvedor da JVM.
     *
     * @param request requisicao com timeout positivo
     * @param maxBytes limite de bytes recebidos, entre zero e {@link Integer#MAX_VALUE}
     * @return corpo completo dentro do limite
     * @throws DownloadPolicyException se a URL, o tamanho ou um redirect for bloqueado
     * @throws IOException em erro HTTP, falha de transporte ou timeout
     * @throws InterruptedException se o chamador for interrompido; cancela a transferencia
     */
    public byte[] send(HttpRequest request, long maxBytes) throws IOException, InterruptedException {
        policy.validateUrl(request.uri().toString());
        return sendBounded(client, request, maxBytes);
    }

    // O acervo administrativo usa TLS dedicado, sem a politica DNS das extensoes X.509.
    static byte[] sendBounded(HttpClient client, HttpRequest request, long maxBytes)
            throws IOException, InterruptedException {
        Duration timeout = request.timeout().orElseThrow(
                () -> new IllegalArgumentException("Timeout obrigatorio para download de certificados"));
        if (maxBytes < 0 || maxBytes > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Limite de resposta fora do intervalo suportado");
        }
        BoundedBodySubscriber subscriber = new BoundedBodySubscriber(maxBytes);
        long started = System.nanoTime();
        CompletableFuture<HttpResponse<byte[]>> pending = client.sendAsync(request, info -> subscriber);
        try {
            // HttpRequest.timeout sozinho nao garante prazo para um corpo que nunca termina.
            long remaining = timeout.toNanos() - (System.nanoTime() - started);
            HttpResponse<byte[]> response = pending.get(Math.max(0, remaining), TimeUnit.NANOSECONDS);
            if (response.statusCode() >= 300 && response.statusCode() < 400) {
                throw new DownloadPolicyException("Redirect HTTP bloqueado: " + response.statusCode());
            }
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode() + " para " + request.uri());
            }
            return response.body();
        } catch (TimeoutException e) {
            throw new HttpTimeoutException("Prazo total do download excedido");
        } catch (ExecutionException e) {
            // O HttpClient pode encapsular a rejeicao do subscriber em IOException.
            for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
                if (cause instanceof DownloadPolicyException blocked) {
                    throw blocked;
                }
            }
            if (e.getCause() instanceof IOException failure) {
                throw failure;
            }
            throw new IOException("Falha no download de certificado", e.getCause());
        } finally {
            subscriber.cancel();
            pending.cancel(true);
        }
    }

    private static final class BoundedBodySubscriber implements BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final long maxBytes;
        private byte[] bytes = new byte[0];
        private int received;
        private Subscription subscription;
        private boolean done;

        private BoundedBodySubscriber(long maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public synchronized void onSubscribe(Subscription subscription) {
            if (done || this.subscription != null) {
                subscription.cancel();
                return;
            }
            this.subscription = subscription;
            subscription.request(1);
        }

        @Override
        public synchronized void onNext(List<ByteBuffer> buffers) {
            if (done) {
                return;
            }
            // Nenhum buffer do lote excedente chega ao acumulador, mesmo sem Content-Length.
            long required = received;
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > maxBytes - required) {
                    subscription.cancel();
                    onError(new DownloadPolicyException("Resposta excede o limite de " + maxBytes + " bytes"));
                    return;
                }
                required += buffer.remaining();
            }
            if (required > bytes.length) {
                int capacity = (int) Math.min(maxBytes,
                        Math.max(required, Math.max(8192L, bytes.length * 2L)));
                bytes = Arrays.copyOf(bytes, capacity);
            }
            // Copia imediatamente: reter buffers por fragmento amplifica memoria em corpos muito fragmentados.
            for (ByteBuffer buffer : buffers) {
                int length = buffer.remaining();
                buffer.get(bytes, received, length);
                received += length;
            }
            subscription.request(1);
        }

        @Override
        public synchronized void onError(Throwable throwable) {
            if (!done) {
                done = true;
                bytes = null;
                body.completeExceptionally(throwable);
            }
        }

        @Override
        public synchronized void onComplete() {
            if (!done) {
                done = true;
                byte[] result = bytes.length == received ? bytes : Arrays.copyOf(bytes, received);
                bytes = null;
                body.complete(result);
            }
        }

        private synchronized void cancel() {
            if (!done) {
                if (subscription != null) {
                    subscription.cancel();
                }
                onError(new IOException("Download cancelado"));
            }
        }
    }
}
