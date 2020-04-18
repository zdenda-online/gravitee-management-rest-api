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
package io.gravitee.rest.api.portal.rest.mapper;

import io.gravitee.definition.model.Proxy;
import io.gravitee.definition.model.VirtualHost;
import io.gravitee.rest.api.model.PrimaryOwnerEntity;
import io.gravitee.rest.api.model.RatingSummaryEntity;
import io.gravitee.rest.api.model.UserEntity;
import io.gravitee.rest.api.model.ViewEntity;
import io.gravitee.rest.api.model.api.ApiEntity;
import io.gravitee.rest.api.model.api.ApiEntrypointEntity;
import io.gravitee.rest.api.model.api.ApiLifecycleState;
import io.gravitee.rest.api.model.parameters.Key;
import io.gravitee.rest.api.portal.rest.model.*;
import io.gravitee.rest.api.service.ParameterService;
import io.gravitee.rest.api.service.RatingService;
import io.gravitee.rest.api.service.SubscriptionService;
import io.gravitee.rest.api.service.ViewService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.ws.rs.core.UriBuilder;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
/**
 * @author Florent CHAMFROY (florent.chamfroy at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class ApiMapperTest {

    private static final String API = "my-api";
    private static final String API_ENTRYPOINT_1 = "http://foo.bar/foo";
    private static final String API_ID = "my-api-id";
    private static final String API_DESCRIPTION = "my-api-description";
    private static final String API_LABEL = "my-api-label";
    private static final String API_NAME = "my-api-name";
    private static final String API_VERSION = "my-api-version";
    private static final String API_OWNER_ID = "my-api-owner-id";
    private static final String API_OWNER_EMAIL = "my-api-ownber-email";
    private static final String API_OWNER_FIRSTNAME = "my-api-owner-firstname";
    private static final String API_OWNER_LASTNAME = "my-api-owner-lastname";
    private static final String API_VIEW = "my-api-view";
    private static final String API_VIEW_HIDDEN = "my-api-view-hidden";

    private static final String API_BASE_URL = "http://foo/bar";

    private ApiEntity apiEntity;

    @Mock
    private RatingService ratingService;

    @Mock
    private SubscriptionService subscriptionService;

    @Mock
    private ParameterService parameterService;

    @Mock
    private ViewService viewService;

    @Mock
    private ViewMapper viewMapper;

    @InjectMocks
    private ApiMapper apiMapper;

    @Test
    public void testConvert() {
        Instant now = Instant.now();
        Date nowDate = Date.from(now);

        // init
        apiEntity = new ApiEntity();
        apiEntity.setId(API_ID);
        apiEntity.setDescription(API_DESCRIPTION);
        apiEntity.setName(API_NAME);
        apiEntity.setLabels(new ArrayList<>(Arrays.asList(API_LABEL)));
        
        ViewEntity view = new ViewEntity();
        view.setHidden(false);
        view.setId(API_VIEW);
        doReturn(view).when(viewService).findById(API_VIEW);
        
        ViewEntity hiddenView = new ViewEntity();
        hiddenView.setHidden(false);
        hiddenView.setId(API_VIEW);
        doReturn(hiddenView).when(viewService).findById(API_VIEW_HIDDEN);

        when(viewMapper.convert(any(),  any())).thenCallRealMethod();
        apiEntity.setViews(new HashSet<>(Arrays.asList(API_VIEW, API_VIEW_HIDDEN)));

        apiEntity.setEntrypoints(
                Arrays.asList(new ApiEntrypointEntity(API_ENTRYPOINT_1), new ApiEntrypointEntity(API + "/foo")));

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("meta", API);
        apiEntity.setMetadata(metadata);
        apiEntity.setVersion(API_VERSION);

        UserEntity ownerEntity = new UserEntity();
        ownerEntity.setId(API_OWNER_ID);
        ownerEntity.setEmail(API_OWNER_EMAIL);
        ownerEntity.setFirstname(API_OWNER_FIRSTNAME);
        ownerEntity.setLastname(API_OWNER_LASTNAME);
        apiEntity.setPrimaryOwner(new PrimaryOwnerEntity(ownerEntity));

        RatingSummaryEntity ratingSummaryEntity = new RatingSummaryEntity();
        ratingSummaryEntity.setAverageRate(Double.valueOf(4.2));
        ratingSummaryEntity.setNumberOfRatings(10);
        doReturn(true).when(ratingService).isEnabled();
        doReturn(ratingSummaryEntity).when(ratingService).findSummaryByApi(API_ID);

        doReturn(true).when(parameterService).findAsBoolean(Key.PORTAL_APIS_VIEW_ENABLED);
        Proxy proxy = new Proxy();
        proxy.setVirtualHosts(Collections.singletonList(new VirtualHost("/foo")));
        apiEntity.setProxy(proxy);
        apiEntity.setLifecycleState(ApiLifecycleState.PUBLISHED);
        apiEntity.setUpdatedAt(nowDate);

        // Test
        Api responseApi = apiMapper.convert(apiEntity, UriBuilder.fromPath(API_BASE_URL));
        assertNotNull(responseApi);

        assertNull(responseApi.getPages());
        assertNull(responseApi.getPlans());

        assertEquals(API_DESCRIPTION, responseApi.getDescription());
        assertEquals(API_ID, responseApi.getId());
        assertEquals(API_NAME, responseApi.getName());
        assertEquals(API_VERSION, responseApi.getVersion());
        assertFalse(responseApi.getDraft());

        List<String> entrypoints = responseApi.getEntrypoints();
        assertNotNull(entrypoints);
        assertEquals(2, entrypoints.size());
        assertEquals(API_ENTRYPOINT_1, entrypoints.get(0));
        assertEquals(API + "/foo", entrypoints.get(1));

        List<String> labels = responseApi.getLabels();
        assertNotNull(labels);
        assertTrue(labels.contains(API_LABEL));

        User owner = responseApi.getOwner();
        assertNotNull(owner);
        assertEquals(API_OWNER_ID, owner.getId());
        assertEquals(API_OWNER_EMAIL, owner.getEmail());
        assertEquals(API_OWNER_FIRSTNAME + ' ' + API_OWNER_LASTNAME, owner.getDisplayName());

        assertEquals(now.toEpochMilli(), responseApi.getUpdatedAt().toInstant().toEpochMilli());

        List<View> views = responseApi.getViews();
        assertNotNull(views);
        assertEquals(API_VIEW, views.get(0).getId());

        RatingSummary ratingSummary = responseApi.getRatingSummary();
        assertNotNull(ratingSummary);
        assertEquals(Double.valueOf(4.2), ratingSummary.getAverage());
        assertEquals(BigDecimal.valueOf(10), ratingSummary.getCount());

        ApiLinks links = responseApi.getLinks();
        testLinks(API_BASE_URL + "/environments/DEFAULT/apis/" + API_ID, links);
    }

    @Test
    public void testMinimalConvert() {
        // init
        apiEntity = new ApiEntity();
        apiEntity.setId(API_ID);
        apiEntity.setDescription(API_DESCRIPTION);
        Proxy proxy = new Proxy();
        proxy.setVirtualHosts(Collections.singletonList(new VirtualHost("/foo")));
        apiEntity.setProxy(proxy);

        doReturn(false).when(ratingService).isEnabled();

        doReturn(false).when(parameterService).findAsBoolean(Key.PORTAL_APIS_VIEW_ENABLED);

        apiEntity.setLifecycleState(ApiLifecycleState.CREATED);

        // Test
        Api responseApi = apiMapper.convert(apiEntity, UriBuilder.fromPath(API_BASE_URL));
        assertNotNull(responseApi);

        assertNull(responseApi.getPages());
        assertNull(responseApi.getPlans());

        assertEquals(API_DESCRIPTION, responseApi.getDescription());
        assertEquals(API_ID, responseApi.getId());
        assertNull(responseApi.getName());
        assertNull(responseApi.getVersion());
        assertTrue(responseApi.getDraft());

        List<String> entrypoints = responseApi.getEntrypoints();
        assertNull(entrypoints);

        List<String> labels = responseApi.getLabels();
        assertNotNull(labels);
        assertEquals(0, labels.size());

        assertNull(responseApi.getOwner());

        List<View> views = responseApi.getViews();
        assertNotNull(views);
        assertEquals(0, views.size());

        RatingSummary ratingSummary = responseApi.getRatingSummary();
        assertNull(ratingSummary);

        ApiLinks links = responseApi.getLinks();
        testLinks(API_BASE_URL + "/environments/DEFAULT/apis/" + API_ID, links);
    }

    @Test
    public void testApiLinks() {
        String basePath = "/" + API;
        ApiLinks links = apiMapper.computeApiLinks(basePath);
        testLinks(basePath, links);
    }
    
    private void testLinks(String basePath, ApiLinks links) {
        assertNotNull(links);

        assertEquals(basePath, links.getSelf());
        assertEquals(basePath + "/metrics", links.getMetrics());
        assertEquals(basePath + "/links", links.getLinks());
        assertEquals(basePath + "/pages", links.getPages());
        assertEquals(basePath + "/picture", links.getPicture());
        assertEquals(basePath + "/plans", links.getPlans());
        assertEquals(basePath + "/ratings", links.getRatings());
    }
    
}
