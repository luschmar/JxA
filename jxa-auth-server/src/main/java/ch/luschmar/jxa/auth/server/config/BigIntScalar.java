package ch.luschmar.jxa.auth.server.config;

import graphql.GraphQLContext;
import graphql.execution.CoercedVariables;
import graphql.language.StringValue;
import graphql.language.Value;
import graphql.schema.*;

import java.math.BigInteger;
import java.util.Locale;

public class BigIntScalar {

    public static final GraphQLScalarType BigInt = GraphQLScalarType.newScalar()
            .name("BigInt")
            .description("A custom scalar that handles emails")
            .coercing(new Coercing() {
                @Override
                public Object serialize(Object dataFetcherResult, GraphQLContext graphQLContext, Locale locale) {
                    throw new CoercingSerializeException("Not implemented");
                }

                @Override
                public Object parseValue(Object input, GraphQLContext graphQLContext, Locale locale) {
                    if (input instanceof BigInteger) {
                        return input;
                    }
                    throw new CoercingParseValueException("Unable to parse variable value " + input + " as an BigInteger");
                }

                @Override
                public Object parseLiteral(Value input, CoercedVariables variables, GraphQLContext graphQLContext, Locale locale) {
                    if (input instanceof StringValue strInput) {
                        var possibleBigInteger = strInput.getValue();
                        return new BigInteger(possibleBigInteger);
                    }
                    throw new CoercingParseLiteralException("Value is not a BigInteger : '" + String.valueOf(input) + "'");
                }
            })
            .build();
}