package ch.luschmar.jxa.crypto;


import java.util.function.Function;

public class FactoryHKDFConverter<T extends HKDFInput, R extends HKDFResult> implements Function<T, R> {
    private final HKDFResultFactory<R> factory;
    private final BytesHKDFConverter<T> function;

    public FactoryHKDFConverter(BytesHKDFConverter<T> function, HKDFResultFactory<R> factory) {
        this.function = function;
        this.factory = factory;
    }

    @Override
    public R apply(T hkdfInput) {
        var result = function.apply(hkdfInput);
        return factory.create(result);
    }
}