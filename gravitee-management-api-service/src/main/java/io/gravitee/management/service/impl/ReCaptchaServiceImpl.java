/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.management.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.management.service.ReCaptchaService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Map;

@Component
public class ReCaptchaServiceImpl implements ReCaptchaService {

    private static Logger LOG = LoggerFactory.getLogger(ReCaptchaServiceImpl.class);

    @Value("${reCaptcha.enabled:false}")
    private boolean enabled;

    @Value("${reCaptcha.publicKey}")
    private String publicKey;

    @Value("${reCaptcha.secretKey}")
    private String secretKey;

    @Value("${reCaptcha.minScore:0.5}")
    private Double minScore;

    @Value("${reCaptcha.serviceUrl:https://www.google.com/recaptcha/api/siteverify}")
    private String serviceUrl;

    @Override
    public boolean isValid(String token) {
        if (!this.isEnabled()) {
            LOG.info("ReCaptchaService is disabled");
            return true;
        }
        LOG.info("ReCaptchaService is enabled");

        try {
            if (token == null || "".equals(token.trim())) {
                LOG.info("Token is empty");
                return false;
            }

            URL obj = new URL(serviceUrl);
            HttpsURLConnection con = null;

            con = (HttpsURLConnection) obj.openConnection();


            con.setRequestMethod("POST");
            con.setRequestProperty("Accept-Language", "en-US,en;q=0.5");

            //add client result as post parameter
            String postParams = "secret=" + secretKey + "&response=" + token;

            // send post request to google recaptcha server
            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(postParams);
            wr.flush();
            wr.close();

            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            ObjectMapper om = new ObjectMapper();
            Map res = om.readValue(response.toString(), Map.class);

            Boolean success = (Boolean) res.get("success");
            Double score = (Double) res.get("score");

            LOG.info(String.format("ReCaptchaService success:%s score:%s", success, score));
            //result should be sucessfull and spam score above 0.5
            return (success && score >= minScore);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public String getPublicKey() {
        return publicKey;
    }

}
