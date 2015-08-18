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
package io.gravitee.management.rest.resource;

import io.gravitee.management.model.PolicyEntity;
import io.gravitee.management.service.PolicyService;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Set;

/**
 * Defines the REST resources to manage {@code Policy}.
 *
 * @author Azize Elamrani (azize dot elamrani at gmail dot com)
 */
@Path("/policies")
public class PoliciesResource {

    @Inject
    private PolicyService policyService;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Set<PolicyEntity> listAll() {
        return policyService.findAll();
    }

    /*

    @GET
    @Path("/{apiName}")
    public Response listAll(@PathParam("apiName") final String apiName) {
        final Api api = apiService.get(apiName);

        final List<Policy> policies = new ArrayList<>();
        Policy policy = new Policy();
        policy.setName("rate-limit");
        policy.setConfiguration("Rate Limiting Policy");
        policies.add(policy);
        policy = new Policy();
        policy.setName("access-control");
        policy.setConfiguration("Access control");
        policies.add(policy);
        policy = new Policy();
        policy.setName("response-time");
        policy.setConfiguration("Response time");
        policies.add(policy);

        if (api.getPolicies() != null) {
            policies.removeAll(api.getPolicies().values());
        }

        return Response.status(HttpStatusCode.OK_200).entity(policies)
            .header("Access-Control-Allow-Origin", "*").build();
    }
    */
}
