/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.embargo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.sql.SQLException;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.dspace.AbstractDSpaceTest;
import org.dspace.authorize.AuthorizeException;
import org.dspace.authorize.ResourcePolicy;
import org.dspace.authorize.service.AuthorizeService;
import org.dspace.authorize.service.ResourcePolicyService;
import org.dspace.content.Bitstream;
import org.dspace.content.Bundle;
import org.dspace.content.Collection;
import org.dspace.content.DCDate;
import org.dspace.content.DSpaceObject;
import org.dspace.content.Item;
import org.dspace.content.factory.ContentServiceFactory;
import org.dspace.content.service.ItemService;
import org.dspace.core.Constants;
import org.dspace.embargo.factory.EmbargoServiceFactory;
import org.dspace.embargo.service.EmbargoService;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.eperson.service.GroupService;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;

/**
 * Unit tests for {@link UwEmbargoSetter}.
 *
 * The parseTerms() tests only depend on configuration ('embargo.terms.open'
 * and 'embargo.terms.days'), so they run against the test kernel without a
 * database, mirroring {@link DayTableEmbargoSetterTest}.
 *
 * The generatePolicies() tests pass the embargo terms explicitly to the
 * terms-aware overload, inject mock services into the protected
 * authorizeService/resourcePolicyService fields inherited from
 * DefaultEmbargoSetter, and statically mock EPersonServiceFactory for group
 * lookups, so no database is needed there either.
 *
 * The setEmbargo() tests additionally mock the Item (with its bundles and
 * bitstreams) and statically mock EmbargoServiceFactory (lift date lookup)
 * and ContentServiceFactory (terms metadata lookup) to prove the terms flow
 * from the item's metadata through to the generated policies.
 */
public class UwEmbargoSetterTest extends AbstractDSpaceTest {

    private static final String TERMS_OPEN_PROPERTY = "embargo.terms.open";
    private static final String TERMS_DAYS_PROPERTY = "embargo.terms.days";
    private static final String TERMS_FIELD_PROPERTY = "embargo.field.terms";

    private static final String TERMS_FIELD = "dc.description.embargo";

    private static final String UW_USERS_GROUP = "UW_Users";

    private static final String RESTRICT_1_YEAR = "Restrict to UW for 1 year -- then make Open Access";
    private static final String RESTRICT_2_YEARS = "Restrict to UW for 2 years -- then make Open Access";
    private static final String RESTRICT_5_YEARS = "Restrict to UW for 5 years -- then make Open Access";
    private static final String DELAY_1_YEAR = "Delay release for 1 year -- then make Open Access";
    private static final String DELAY_2_YEARS = "Delay release for 2 years -- then make Open Access";

    /**
     * Tolerance when comparing computed lift dates against "now + N days",
     * to absorb the wall-clock time that passes while the test runs.
     */
    private static final Duration TOLERANCE = Duration.ofMinutes(5);

    private ConfigurationService configurationService;
    private UwEmbargoSetter embargoSetter;

    private Object previousTermsOpen;
    private Object previousTermsDays;
    private Object previousTermsField;

    // Mocked collaborators for the generatePolicies() tests
    private AuthorizeService authorizeService;
    private ResourcePolicyService resourcePolicyService;
    private GroupService groupService;
    private Group anonymousGroup;
    private Group uwUsersGroup;
    private DSpaceObject dso;
    private Collection owningCollection;

    // Mocked item structure for the setEmbargo() tests
    private Item item;
    private Bundle licenseBundle;
    private Bundle originalBundle;
    private Bitstream originalBitstream;

    @Before
    public void setUp() throws SQLException {
        configurationService = DSpaceServicesFactory.getInstance().getConfigurationService();
        previousTermsOpen = configurationService.getPropertyValue(TERMS_OPEN_PROPERTY);
        previousTermsDays = configurationService.getPropertyValue(TERMS_DAYS_PROPERTY);
        previousTermsField = configurationService.getPropertyValue(TERMS_FIELD_PROPERTY);

        configurationService.setProperty(TERMS_OPEN_PROPERTY, "forever");
        configurationService.setProperty(TERMS_DAYS_PROPERTY, new String[] {
            RESTRICT_1_YEAR + ":365",
            RESTRICT_2_YEARS + ":720",
            RESTRICT_5_YEARS + ":1800",
            DELAY_1_YEAR + ":365",
            DELAY_2_YEARS + ":720"});
        configurationService.setProperty(TERMS_FIELD_PROPERTY, TERMS_FIELD);

        embargoSetter = new UwEmbargoSetter();

        // Inject mocks into the protected service fields inherited from
        // DefaultEmbargoSetter so the lazy getters never hit the real factory.
        authorizeService = mock(AuthorizeService.class);
        resourcePolicyService = mock(ResourcePolicyService.class);
        embargoSetter.authorizeService = authorizeService;
        embargoSetter.resourcePolicyService = resourcePolicyService;

        groupService = mock(GroupService.class);
        anonymousGroup = mock(Group.class);
        when(anonymousGroup.getName()).thenReturn(Group.ANONYMOUS);
        when(anonymousGroup.getID()).thenReturn(UUID.randomUUID());
        uwUsersGroup = mock(Group.class);
        when(uwUsersGroup.getName()).thenReturn(UW_USERS_GROUP);
        when(uwUsersGroup.getID()).thenReturn(UUID.randomUUID());
        when(groupService.findByName(any(), eq(Group.ANONYMOUS))).thenReturn(anonymousGroup);
        when(groupService.findByName(any(), eq(UW_USERS_GROUP))).thenReturn(uwUsersGroup);

        dso = mock(DSpaceObject.class);
        owningCollection = mock(Collection.class);
    }

    @After
    public void tearDown() {
        configurationService.setProperty(TERMS_OPEN_PROPERTY, previousTermsOpen);
        configurationService.setProperty(TERMS_DAYS_PROPERTY, previousTermsDays);
        configurationService.setProperty(TERMS_FIELD_PROPERTY, previousTermsField);
    }

    // ---------------------------------------------------------------
    // parseTerms()
    // ---------------------------------------------------------------

    /**
     * Terms matching the configured 'embargo.terms.open' value mean a
     * permanent embargo: the lift date is the special FOREVER date rather
     * than a computed one.
     */
    @Test
    public void parseTermsReturnsForeverForOpenTerms() throws SQLException, AuthorizeException {
        DCDate result = embargoSetter.parseTerms(null, null, "forever");
        assertEquals("Open terms should return the FOREVER date",
                     EmbargoServiceImpl.FOREVER.toString(), result.toString());
    }

    /**
     * Each of the five standard UW embargo choices maps through the
     * 'embargo.terms.days' table to a lift date the configured number of days
     * from now. Both "Restrict to UW" and "Delay release" variants use the
     * same table; they differ in who may read during the embargo (see the
     * generatePolicies() tests), not in the lift date.
     */
    @Test
    public void parseTermsComputesLiftDateForEachConfiguredTerm() throws SQLException, AuthorizeException {
        String[][] termsAndDays = {
            {RESTRICT_1_YEAR, "365"},
            {RESTRICT_2_YEARS, "720"},
            {RESTRICT_5_YEARS, "1800"},
            {DELAY_1_YEAR, "365"},
            {DELAY_2_YEARS, "720"}};
        for (String[] entry : termsAndDays) {
            DCDate result = embargoSetter.parseTerms(null, null, entry[0]);
            assertNotNull("Terms '" + entry[0] + "' should produce a lift date", result);

            ZonedDateTime expected = ZonedDateTime.now().plusDays(Long.parseLong(entry[1]));
            Duration difference = Duration.between(expected, result.toDate()).abs();
            assertTrue("Lift date for '" + entry[0] + "' should be " + entry[1]
                           + " days from now, but was " + result.toDate()
                           + " (off by " + difference + ")",
                       difference.compareTo(TOLERANCE) <= 0);
        }
    }

    /**
     * Terms text absent from the day table produces no lift date: the setter
     * must not guess at a date for wording it does not recognize.
     */
    @Test
    public void parseTermsReturnsNullForUnknownTerms() throws SQLException, AuthorizeException {
        assertNull("Terms not in the day table should return null",
                   embargoSetter.parseTerms(null, null, "3 fortnights"));
    }

    /**
     * An item with no embargo terms metadata is simply not embargoed.
     */
    @Test
    public void parseTermsReturnsNullForNullTerms() throws SQLException, AuthorizeException {
        assertNull("Null terms should return null",
                   embargoSetter.parseTerms(null, null, null));
    }

    // ---------------------------------------------------------------
    // generatePolicies()
    // ---------------------------------------------------------------

    /**
     * Without an embargo date there is nothing to enforce: no policies may be
     * created or modified.
     */
    @Test
    public void generatePoliciesDoesNothingForNullEmbargoDate() throws SQLException, AuthorizeException {
        embargoSetter.generatePolicies(null, null, "reason", dso, owningCollection, RESTRICT_1_YEAR);

        verifyNoInteractions(authorizeService);
        verifyNoInteractions(resourcePolicyService);
    }

    /**
     * The core "Restrict to UW" behavior: Anonymous gets a READ policy that
     * only starts on the lift date (the public is blocked until then), while
     * UW_Users gets a READ policy with no start date (immediate access).
     */
    @Test
    public void restrictToUwCreatesEmbargoedAnonymousAndOpenUwPolicies()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(365);
        stubAuthorizedGroups(anonymousGroup, uwUsersGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        ResourcePolicy uwPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy, dso);
        stubCreatePolicy(uwUsersGroup, null, uwPolicy, dso);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection, RESTRICT_1_YEAR);
        }

        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(anonymousGroup),
                                                      isNull(), eq(embargoDate), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(uwUsersGroup),
                                                      isNull(), isNull(), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(resourcePolicyService).update(any(), same(anonymousPolicy));
        verify(resourcePolicyService).update(any(), same(uwPolicy));
    }

    /**
     * "Restrict to UW" terms only grant UW_Users immediate access when that
     * group is already authorized for DEFAULT_ITEM_READ on the owning
     * collection; the embargo wording alone must not widen access. The
     * embargoed Anonymous policy is still created.
     */
    @Test
    public void restrictToUwSkipsUwPolicyWhenUwUsersNotAuthorized()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(720);
        stubAuthorizedGroups(anonymousGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy, dso);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection, RESTRICT_2_YEARS);
        }

        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(anonymousGroup),
                                                      isNull(), eq(embargoDate), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(authorizeService, never()).createOrModifyPolicy(any(), any(), any(), same(uwUsersGroup),
                                                               any(), any(), eq(Constants.READ),
                                                               any(), any());
        verify(resourcePolicyService).update(any(), same(anonymousPolicy));
    }

    /**
     * "Delay release" is the key contrast with "Restrict to UW": nobody gets
     * early access, not even UW_Users, even when that group is authorized on
     * the owning collection. Only the embargoed Anonymous policy is created.
     */
    @Test
    public void delayReleaseCreatesOnlyEmbargoedAnonymousPolicy()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(365);
        stubAuthorizedGroups(anonymousGroup, uwUsersGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy, dso);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection, DELAY_1_YEAR);
        }

        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(anonymousGroup),
                                                      isNull(), eq(embargoDate), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(authorizeService, never()).createOrModifyPolicy(any(), any(), any(), same(uwUsersGroup),
                                                               any(), any(), eq(Constants.READ),
                                                               any(), any());
        verify(resourcePolicyService, times(1)).update(any(), any(ResourcePolicy.class));
    }

    /**
     * When the owning collection does not authorize Anonymous at all, a
     * "Restrict to UW" embargo still grants UW_Users immediate access; no
     * Anonymous policy is created.
     */
    @Test
    public void restrictToUwWithoutAnonymousStillCreatesUwPolicy()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(1800);
        stubAuthorizedGroups(uwUsersGroup);
        ResourcePolicy uwPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(uwUsersGroup, null, uwPolicy, dso);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection, RESTRICT_5_YEARS);
        }

        verify(authorizeService, never()).createOrModifyPolicy(any(), any(), any(), same(anonymousGroup),
                                                               any(), any(), eq(Constants.READ),
                                                               any(), any());
        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(uwUsersGroup),
                                                      isNull(), isNull(), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(resourcePolicyService).update(any(), same(uwPolicy));
    }

    /**
     * The legacy 5-arg generatePolicies() has no terms available, so it must
     * fail safe: never grant UW_Users immediate access, even when the group is
     * authorized on the owning collection.
     */
    @Test
    public void legacyGeneratePoliciesCreatesNoUwPolicy()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(365);
        stubAuthorizedGroups(anonymousGroup, uwUsersGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy, dso);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection);
        }

        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(anonymousGroup),
                                                      isNull(), eq(embargoDate), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(authorizeService, never()).createOrModifyPolicy(any(), any(), any(), same(uwUsersGroup),
                                                               any(), any(), eq(Constants.READ),
                                                               any(), any());
        verify(resourcePolicyService, times(1)).update(any(), any(ResourcePolicy.class));
    }

    // ---------------------------------------------------------------
    // setEmbargo()
    // ---------------------------------------------------------------

    /**
     * End-to-end over the mocked item: the "Restrict to UW" terms stored in
     * the item's metadata flow through setEmbargo() to the ORIGINAL
     * bitstream's policies — an embargoed Anonymous policy plus an immediate
     * UW_Users policy.
     */
    @Test
    public void setEmbargoPassesRestrictTermsThroughToPolicies()
        throws SQLException, AuthorizeException {
        DCDate liftDate = new DCDate(ZonedDateTime.now(ZoneOffset.UTC).plusDays(365));
        LocalDate embargoDate = liftDate.toDate().toLocalDate();
        mockItemWithBundles();
        stubAuthorizedGroups(anonymousGroup, uwUsersGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        ResourcePolicy uwPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy, originalBitstream);
        stubCreatePolicy(uwUsersGroup, null, uwPolicy, originalBitstream);

        try (MockedStatic<EPersonServiceFactory> ePerson = mockGroupService();
             MockedStatic<EmbargoServiceFactory> embargo = mockEmbargoService(liftDate);
             MockedStatic<ContentServiceFactory> content = mockItemService(RESTRICT_1_YEAR)) {
            embargoSetter.setEmbargo(null, item);
        }

        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(anonymousGroup),
                                                      isNull(), eq(embargoDate), eq(Constants.READ),
                                                      isNull(), same(originalBitstream));
        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(uwUsersGroup),
                                                      isNull(), isNull(), eq(Constants.READ),
                                                      isNull(), same(originalBitstream));
        verify(resourcePolicyService).update(any(), same(anonymousPolicy));
        verify(resourcePolicyService).update(any(), same(uwPolicy));
    }

    /**
     * Embargoes apply to content bitstreams only: the LICENSE bundle's
     * policies must be left untouched.
     */
    @Test
    public void setEmbargoSkipsLicenseBundle()
        throws SQLException, AuthorizeException {
        DCDate liftDate = new DCDate(ZonedDateTime.now(ZoneOffset.UTC).plusDays(720));
        LocalDate embargoDate = liftDate.toDate().toLocalDate();
        mockItemWithBundles();
        stubAuthorizedGroups(anonymousGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy, originalBitstream);

        try (MockedStatic<EPersonServiceFactory> ePerson = mockGroupService();
             MockedStatic<EmbargoServiceFactory> embargo = mockEmbargoService(liftDate);
             MockedStatic<ContentServiceFactory> content = mockItemService(DELAY_2_YEARS)) {
            embargoSetter.setEmbargo(null, item);
        }

        // The LICENSE bundle must be skipped entirely: its bitstreams are never
        // even enumerated, and the only policy created targets the ORIGINAL
        // bundle's bitstream.
        verify(licenseBundle, never()).getBitstreams();
        verify(authorizeService, times(1)).createOrModifyPolicy(any(), any(), any(), any(),
                                                                any(), any(), eq(Constants.READ),
                                                                any(), same(originalBitstream));
    }

    /**
     * When the embargo service reports no lift date for the item,
     * setEmbargo() must not touch any policies, even though terms metadata is
     * present.
     */
    @Test
    public void setEmbargoDoesNothingWhenLiftDateIsNull()
        throws SQLException, AuthorizeException {
        mockItemWithBundles();

        try (MockedStatic<EmbargoServiceFactory> embargo = mockEmbargoService(null);
             MockedStatic<ContentServiceFactory> content = mockItemService(RESTRICT_1_YEAR)) {
            embargoSetter.setEmbargo(null, item);
        }

        verifyNoInteractions(authorizeService);
        verifyNoInteractions(resourcePolicyService);
    }

    // ---------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------

    private void stubAuthorizedGroups(Group... groups) throws SQLException {
        List<Group> authorized = Arrays.asList(groups);
        when(authorizeService.getAuthorizedGroups(any(), same(owningCollection),
                                                  eq(Constants.DEFAULT_ITEM_READ)))
            .thenReturn(authorized);
    }

    private void stubCreatePolicy(Group group, LocalDate embargoDate, ResourcePolicy policy,
                                  DSpaceObject target)
        throws SQLException, AuthorizeException {
        when(authorizeService.createOrModifyPolicy(isNull(), any(), isNull(), same(group), isNull(),
                                                   embargoDate == null ? isNull() : eq(embargoDate),
                                                   eq(Constants.READ), any(), same(target)))
            .thenReturn(policy);
    }

    /**
     * Mock an item with a LICENSE bundle and an ORIGINAL bundle holding one
     * bitstream, owned by the mocked owningCollection.
     */
    private void mockItemWithBundles() throws SQLException {
        item = mock(Item.class);
        when(item.getOwningCollection()).thenReturn(owningCollection);
        licenseBundle = mock(Bundle.class);
        when(licenseBundle.getName()).thenReturn(Constants.LICENSE_BUNDLE_NAME);
        originalBundle = mock(Bundle.class);
        when(originalBundle.getName()).thenReturn(Constants.DEFAULT_BUNDLE_NAME);
        originalBitstream = mock(Bitstream.class);
        when(originalBundle.getBitstreams()).thenReturn(List.of(originalBitstream));
        when(item.getBundles()).thenReturn(Arrays.asList(licenseBundle, originalBundle));
    }

    /**
     * Statically mock EPersonServiceFactory so UwEmbargoSetter's group
     * lookups hit the mocked GroupService. Callers must close the returned
     * MockedStatic (use try-with-resources).
     */
    private MockedStatic<EPersonServiceFactory> mockGroupService() {
        EPersonServiceFactory ePersonServiceFactory = mock(EPersonServiceFactory.class);
        when(ePersonServiceFactory.getGroupService()).thenReturn(groupService);
        MockedStatic<EPersonServiceFactory> factory = mockStatic(EPersonServiceFactory.class);
        factory.when(EPersonServiceFactory::getInstance).thenReturn(ePersonServiceFactory);
        return factory;
    }

    /**
     * Statically mock EmbargoServiceFactory so setEmbargo()'s lift-date lookup
     * returns the given date. Callers must close the returned MockedStatic.
     */
    private MockedStatic<EmbargoServiceFactory> mockEmbargoService(DCDate liftDate)
        throws SQLException, AuthorizeException {
        EmbargoService embargoService = mock(EmbargoService.class);
        when(embargoService.getEmbargoTermsAsDate(any(), same(item))).thenReturn(liftDate);
        EmbargoServiceFactory embargoServiceFactory = mock(EmbargoServiceFactory.class);
        when(embargoServiceFactory.getEmbargoService()).thenReturn(embargoService);
        MockedStatic<EmbargoServiceFactory> factory = mockStatic(EmbargoServiceFactory.class);
        factory.when(EmbargoServiceFactory::getInstance).thenReturn(embargoServiceFactory);
        return factory;
    }

    /**
     * Statically mock ContentServiceFactory so setEmbargo()'s terms lookup on
     * the item's metadata (field TERMS_FIELD) returns the given terms.
     * Callers must close the returned MockedStatic.
     */
    private MockedStatic<ContentServiceFactory> mockItemService(String terms) {
        ItemService itemService = mock(ItemService.class);
        when(itemService.getMetadataFirstValue(same(item), eq("dc"), eq("description"),
                                               eq("embargo"), eq(Item.ANY)))
            .thenReturn(terms);
        ContentServiceFactory contentServiceFactory = mock(ContentServiceFactory.class);
        when(contentServiceFactory.getItemService()).thenReturn(itemService);
        MockedStatic<ContentServiceFactory> factory = mockStatic(ContentServiceFactory.class);
        factory.when(ContentServiceFactory::getInstance).thenReturn(contentServiceFactory);
        return factory;
    }
}
