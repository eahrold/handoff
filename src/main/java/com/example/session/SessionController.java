package com.example.session;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.http.uri.UriTemplate;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Controller
@Secured(SecurityRule.IS_ANONYMOUS)
public class SessionController {

    final static String JWT_EXCHANGE_KEY = "JWT_EXCHANGE_KEY";
    public static final String JWT_TOKEN_KEY = "jwt_token_key";

    final static String REDIRECT_HOST = "http://localhost:8080";
    final static String LANGING_PAGE = "";


    Logger logger = LoggerFactory.getLogger(SessionController.class);
    SessionStore<Session> sessionStore;

    public SessionController(SessionStore<Session> sessionStore) {
        this.sessionStore = sessionStore;
    }

    String fetchJwt(String providerToken) {
        return providerToken;
    }

    @Get("/oauth/{provider}/callback{?token}")
    HttpResponse<?> oAuthCallback(Session oAuthSession, @PathVariable String provider, @Nullable @QueryValue String token) {
        String jwt = fetchJwt(token);

        oAuthSession.put(JWT_EXCHANGE_KEY, jwt);

        String path = new UriTemplate( "/synchronize/hand-off/{otc}")
                .expand(Map.of("otc", oAuthSession.getId()));

        URI uri = UriBuilder.of(REDIRECT_HOST)
                .path(path)
                .build();

        return HttpResponse.temporaryRedirect(uri);
    }

    @Get("/synchronize/hand-off/{otc}")
    HttpResponse<?> sessionTokenTransfer(Session currentSession, @PathVariable String otc) {

        Optional<Session> oAuthSessionOptional = sessionStore.findSession(otc).get();
        if(oAuthSessionOptional.isEmpty()) {
            return HttpResponse.notFound();
        }
        Session oAuthSession = oAuthSessionOptional.get();
         String message2 = oAuthSession.get(JWT_EXCHANGE_KEY, String.class).orElse("NOPE");
        // put the key onto the current session
        currentSession.put(JWT_TOKEN_KEY, message2);

        // Cleanup if we're handing off from a different session
        if(!oAuthSession.getId().equals(currentSession.getId())) {
            sessionStore.deleteSession(oAuthSession.getId());
        }

        URI uri = UriBuilder.of(REDIRECT_HOST)
            .path(LANGING_PAGE)
            .build();
        return HttpResponse.temporaryRedirect(uri);
    }

    /**
     * Just a mocked up landing page, we don't need this
     * @param session
     * @return
     */
    @Get("/")
    HttpResponse<String> goose(Session session) {
        return session.get(JWT_EXCHANGE_KEY, String.class)
                .map(HttpResponse::ok)
                .orElse(HttpResponse.notFound());
    }
}
