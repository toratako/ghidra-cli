package ghidracli.runtime;

import com.google.gson.JsonObject;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/** Small controls use connection threads; program/results use the response pool. */
final class BridgeReply {
    final CompletableFuture<Supplier<JsonObject>> completion;
    final boolean asynchronous;

    private BridgeReply(CompletableFuture<Supplier<JsonObject>> completion, boolean asynchronous) {
        this.completion = completion;
        this.asynchronous = asynchronous;
    }

    static BridgeReply immediate(JsonObject response) {
        return new BridgeReply(CompletableFuture.completedFuture(() -> response), false);
    }

    static BridgeReply pending(CompletableFuture<JsonObject> completion) {
        return new BridgeReply(completion.thenApply(response -> () -> response), true);
    }

    static BridgeReply deferred(Supplier<JsonObject> response) {
        return new BridgeReply(CompletableFuture.completedFuture(response), true);
    }
}
