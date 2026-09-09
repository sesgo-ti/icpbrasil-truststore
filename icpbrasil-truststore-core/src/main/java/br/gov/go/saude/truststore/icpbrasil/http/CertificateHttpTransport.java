package br.gov.go.saude.truststore.icpbrasil.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Transporte HTTP para artefatos referenciados em extensões de certificados X.509
 * (AIA CA Issuers, respostas OCSP e CRLs).
 *
 * <p>Como as URLs vêm de certificados de terceiros, cada requisição segue um contrato fechado:</p>
 * <ul>
 *   <li>a URL passa por {@link DownloadPolicy#validateUrl(String)} imediatamente antes de cada envio;</li>
 *   <li>redirecionamentos (3xx) nunca são seguidos e resultam em {@link DownloadPolicyException};</li>
 *   <li>status diferente de 200 falha assim que os cabeçalhos chegam, sem ler o corpo;</li>
 *   <li>o corpo de uma resposta 200 é acumulado em um único array durante o recebimento e a
 *       conexão é cancelada assim que exceder {@code maxBytes}, inclusive em transferência chunked;</li>
 *   <li>o timeout informado cobre a troca inteira (conexão, cabeçalhos e corpo).</li>
 * </ul>
 *
 * <p>Não faz retentativas; isso cabe ao chamador. Instâncias são imutáveis e thread-safe.</p>
 */
public final class CertificateHttpTransport {

    private final HttpClient httpClient;
    private final DownloadPolicy downloadPolicy;

    /**
     * Cria o transporte com um {@link HttpClient} próprio, sem redirecionamentos e com o timeout
     * de conexão informado. O trust store TLS é o padrão da JVM.
     */
    public CertificateHttpTransport(DownloadPolicy downloadPolicy, Duration connectTimeout) {
        this(downloadPolicy, HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(connectTimeout)
                .build());
    }

    /**
     * Cria o transporte sobre um {@link HttpClient} existente.
     *
     * @throws IllegalArgumentException se o cliente seguir redirecionamentos, isto é,
     *         {@link HttpClient#followRedirects()} diferente de {@link HttpClient.Redirect#NEVER}
     */
    public CertificateHttpTransport(DownloadPolicy downloadPolicy, HttpClient httpClient) {
        Objects.requireNonNull(httpClient, "httpClient");
        if (httpClient.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException(
                    "HttpClient deve usar Redirect.NEVER; recebido: " + httpClient.followRedirects());
        }
        this.downloadPolicy = Objects.requireNonNull(downloadPolicy, "downloadPolicy");
        this.httpClient = httpClient;
    }

    /**
     * Executa um GET e devolve o corpo de uma resposta 200.
     *
     * @param url      URL absoluta http(s); validada pela {@link DownloadPolicy} antes do envio
     * @param maxBytes tamanho máximo do corpo; ao ser excedido a conexão é cancelada
     * @param timeout  tempo máximo para a troca completa (conexão, cabeçalhos e corpo)
     * @return corpo da resposta, com no máximo {@code maxBytes} bytes
     * @throws DownloadPolicyException se a URL for bloqueada, a resposta for um redirecionamento
     *         ou o corpo exceder {@code maxBytes}
     * @throws IOException             em falha de rede, timeout ou status HTTP diferente de 200
     * @throws InterruptedException    se a thread for interrompida durante a espera
     */
    public byte[] get(String url, long maxBytes, Duration timeout) throws IOException, InterruptedException {
        return execute(url, HttpRequest.newBuilder().GET(), maxBytes, timeout);
    }

    /**
     * Executa um POST com o corpo informado e devolve o corpo de uma resposta 200.
     *
     * @param url         URL absoluta http(s); validada pela {@link DownloadPolicy} antes do envio
     * @param body        corpo da requisição
     * @param contentType valor do cabeçalho {@code Content-Type} da requisição
     * @param accept      valor do cabeçalho {@code Accept} da requisição
     * @param maxBytes    tamanho máximo do corpo da resposta; ao ser excedido a conexão é cancelada
     * @param timeout     tempo máximo para a troca completa (conexão, cabeçalhos e corpo)
     * @return corpo da resposta, com no máximo {@code maxBytes} bytes
     * @throws DownloadPolicyException se a URL for bloqueada, a resposta for um redirecionamento
     *         ou o corpo exceder {@code maxBytes}
     * @throws IOException             em falha de rede, timeout ou status HTTP diferente de 200
     * @throws InterruptedException    se a thread for interrompida durante a espera
     */
    public byte[] post(String url, byte[] body, String contentType, String accept,
                       long maxBytes, Duration timeout) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder()
                .header("Content-Type", contentType)
                .header("Accept", accept)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        return execute(url, request, maxBytes, timeout);
    }

    private byte[] execute(String url, HttpRequest.Builder requestBuilder, long maxBytes, Duration timeout)
            throws IOException, InterruptedException {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes deve ser positivo: " + maxBytes);
        }
        Objects.requireNonNull(timeout, "timeout");
        downloadPolicy.validateUrl(url);

        HttpRequest request = requestBuilder.uri(URI.create(url)).timeout(timeout).build();
        LimitedBodyHandler handler = new LimitedBodyHandler(maxBytes);

        // HttpRequest.timeout() só cobre até a chegada dos cabeçalhos; a espera limitada no future
        // é o que impõe o prazo ao corpo, e cancel(true) encerra a troca em andamento.
        CompletableFuture<HttpResponse<byte[]>> future = httpClient.sendAsync(request, handler);
        HttpResponse<byte[]> response;
        try {
            response = future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new HttpTimeoutException(
                    "Tempo limite de " + timeout.toMillis() + " ms excedido para " + url);
        } catch (InterruptedException e) {
            future.cancel(true);
            throw e;
        } catch (ExecutionException e) {
            // Após um cancelamento o HttpClient pode falhar a resposta com um IOException genérico
            // antes da exceção do subscriber; por isso o estado registrado pelo handler, e não o
            // tipo da causa, decide o motivo da falha.
            if (handler.rejectedStatus() != 0) {
                throwForStatus(handler.rejectedStatus(), url);
            }
            if (handler.isLimitExceeded()) {
                throw new DownloadPolicyException(
                        "Resposta de " + url + " excede o limite de " + maxBytes + " bytes");
            }
            Throwable cause = rootCause(e);
            if (cause instanceof DownloadPolicyException policyException) {
                throw policyException;
            }
            if (cause instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("Falha na requisição para " + url + ": " + cause, cause);
        }

        if (response.statusCode() != 200) {
            throwForStatus(response.statusCode(), url);
        }
        return response.body();
    }

    private static void throwForStatus(int status, String url) throws IOException {
        if (status >= 300 && status < 400) {
            throw new DownloadPolicyException(
                    "Redirecionamento HTTP " + status + " não seguido para: " + url);
        }
        throw new IOException("HTTP " + status + " para " + url);
    }

    private static Throwable rootCause(Throwable throwable) {
        Throwable cause = throwable;
        while ((cause instanceof ExecutionException || cause instanceof CompletionException)
                && cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }

    /**
     * Decide pelo status, antes de qualquer byte do corpo, como a resposta será consumida: só o
     * 200 é acumulado; os demais são cancelados de imediato. Registra o motivo da rejeição para o
     * transporte, pois a causa propagada pelo future não é confiável após um cancelamento.
     */
    static final class LimitedBodyHandler implements HttpResponse.BodyHandler<byte[]> {

        private final long maxBytes;
        private volatile int rejectedStatus;
        private volatile LimitedBodySubscriber accepted;

        LimitedBodyHandler(long maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public HttpResponse.BodySubscriber<byte[]> apply(HttpResponse.ResponseInfo responseInfo) {
            int status = responseInfo.statusCode();
            if (status != 200) {
                rejectedStatus = status;
                return new RejectingBodySubscriber(status);
            }
            LimitedBodySubscriber subscriber = new LimitedBodySubscriber(maxBytes);
            accepted = subscriber;
            return subscriber;
        }

        int rejectedStatus() {
            return rejectedStatus;
        }

        boolean isLimitExceeded() {
            LimitedBodySubscriber subscriber = accepted;
            return subscriber != null && subscriber.isLimitExceeded();
        }
    }

    /**
     * Cancela a assinatura já em {@code onSubscribe}: o corpo de uma resposta rejeitada não
     * interessa e lê-lo custaria até {@code maxBytes} de uma página de erro.
     */
    static final class RejectingBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {

        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final int status;

        RejectingBodySubscriber(int status) {
            this.status = status;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            // Falhar antes de cancelar: após o cancelamento o HttpClient não completa a resposta sozinho.
            fail();
            subscription.cancel();
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            fail();
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        private void fail() {
            result.completeExceptionally(new IOException("HTTP " + status + " recebido; corpo descartado"));
        }
    }

    /**
     * Acumula o corpo em um único array que cresce geometricamente até {@code maxBytes}.
     *
     * <p>Os {@link ByteBuffer}s recebidos são copiados e liberados na hora, nunca retidos, e a
     * capacidade nunca é reservada a partir de Content-Length, que é controlado pelo servidor.
     * Ao exceder o limite, o resultado é falhado e a assinatura cancelada, o que faz o HttpClient
     * fechar a conexão.</p>
     */
    static final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {

        private static final int INITIAL_CAPACITY = 8 * 1024;
        private static final int MAX_ARRAY_LENGTH = Integer.MAX_VALUE - 8;

        private final int maxBytes;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private volatile boolean limitExceeded;

        // Acessados apenas pelos callbacks de Flow.Subscriber, que a especificação serializa.
        private Flow.Subscription subscription;
        private byte[] buffer = new byte[0];
        private int size;
        private boolean done;

        LimitedBodySubscriber(long maxBytes) {
            this.maxBytes = (int) Math.min(maxBytes, MAX_ARRAY_LENGTH);
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (done) {
                return;
            }
            for (ByteBuffer item : items) {
                int length = item.remaining();
                if (length > maxBytes - size) {
                    rejectExcess();
                    return;
                }
                ensureCapacity(size + length);
                item.get(buffer, size, length);
                size += length;
            }
        }

        @Override
        public void onError(Throwable throwable) {
            if (done) {
                return;
            }
            done = true;
            buffer = null;
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            if (done) {
                return;
            }
            done = true;
            byte[] body = size == buffer.length ? buffer : Arrays.copyOf(buffer, size);
            buffer = null;
            result.complete(body);
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        boolean isLimitExceeded() {
            return limitExceeded;
        }

        private void rejectExcess() {
            done = true;
            buffer = null;
            limitExceeded = true;
            // Falhar o resultado antes de cancelar: o cancelamento faz o HttpClient reportar um
            // IOException genérico que, se chegasse primeiro ao future, mascararia a causa real.
            result.completeExceptionally(
                    new DownloadPolicyException("Resposta excede o limite de " + maxBytes + " bytes"));
            subscription.cancel();
        }

        private void ensureCapacity(int required) {
            if (required <= buffer.length) {
                return;
            }
            long doubled = Math.max(INITIAL_CAPACITY, 2L * buffer.length);
            int capacity = (int) Math.max(required, Math.min(doubled, maxBytes));
            buffer = Arrays.copyOf(buffer, capacity);
        }
    }
}
