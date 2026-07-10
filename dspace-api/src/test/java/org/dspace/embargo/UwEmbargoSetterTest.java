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
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.dspace.AbstractDSpaceTest;
import org.dspace.authorize.AuthorizeException;
import org.dspace.authorize.ResourcePolicy;
import org.dspace.authorize.service.AuthorizeService;
import org.dspace.authorize.service.ResourcePolicyService;
import org.dspace.content.Collection;
import org.dspace.content.DCDate;
import org.dspace.content.DSpaceObject;
import org.dspace.core.Constants;
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
 * The generatePolicies() tests inject mock services into the protected
 * authorizeService/resourcePolicyService fields inherited from
 * DefaultEmbargoSetter, and statically mock EPersonServiceFactory for group
 * lookups, so no database is needed there either.
 */
public class UwEmbargoSetterTest extends AbstractDSpaceTest {

    private static final String TERMS_OPEN_PROPERTY = "embargo.terms.open";
    private static final String TERMS_DAYS_PROPERTY = "embargo.terms.days";

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

    // Mocked collaborators for the generatePolicies() tests
    private AuthorizeService authorizeService;
    private ResourcePolicyService resourcePolicyService;
    private GroupService groupService;
    private Group anonymousGroup;
    private Group uwUsersGroup;
    private DSpaceObject dso;
    private Collection owningCollection;

    @Before
    public void setUp() throws SQLException {
        configurationService = DSpaceServicesFactory.getInstance().getConfigurationService();
        previousTermsOpen = configurationService.getPropertyValue(TERMS_OPEN_PROPERTY);
        previousTermsDays = configurationService.getPropertyValue(TERMS_DAYS_PROPERTY);

        configurationService.setProperty(TERMS_OPEN_PROPERTY, "forever");
        configurationService.setProperty(TERMS_DAYS_PROPERTY, new String[] {
            RESTRICT_1_YEAR + ":365",
            RESTRICT_2_YEARS + ":720",
            RESTRICT_5_YEARS + ":1800",
            DELAY_1_YEAR + ":365",
            DELAY_2_YEARS + ":720"});

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
    }

    // ---------------------------------------------------------------
    // parseTerms()
    // ---------------------------------------------------------------

    @Test
    public void parseTermsReturnsForeverForOpenTerms() throws SQLException, AuthorizeException {
        DCDate result = embargoSetter.parseTerms(null, null, "forever");
        assertEquals("Open terms should return the FOREVER date",
                     EmbargoServiceImpl.FOREVER.toString(), result.toString());
    }

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

    @Test
    public void parseTermsReturnsNullForUnknownTerms() throws SQLException, AuthorizeException {
        assertNull("Terms not in the day table should return null",
                   embargoSetter.parseTerms(null, null, "3 fortnights"));
    }

    @Test
    public void parseTermsReturnsNullForNullTerms() throws SQLException, AuthorizeException {
        assertNull("Null terms should return null",
                   embargoSetter.parseTerms(null, null, null));
    }

    // ---------------------------------------------------------------
    // generatePolicies()
    // ---------------------------------------------------------------

    @Test
    public void generatePoliciesDoesNothingForNullEmbargoDate() throws SQLException, AuthorizeException {
        embargoSetter.generatePolicies(null, null, "reason", dso, owningCollection);

        verifyNoInteractions(authorizeService);
        verifyNoInteractions(resourcePolicyService);
    }

    @Test
    public void restrictToUwCreatesEmbargoedAnonymousAndOpenUwPolicies()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(365);
        stubAuthorizedGroups(anonymousGroup, uwUsersGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        ResourcePolicy uwPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy);
        stubCreatePolicy(uwUsersGroup, null, uwPolicy);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.parseTerms(null, null, RESTRICT_1_YEAR);
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection);
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

    @Test
    public void restrictToUwSkipsUwPolicyWhenUwUsersNotAuthorized()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(720);
        stubAuthorizedGroups(anonymousGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.parseTerms(null, null, RESTRICT_2_YEARS);
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection);
        }

        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(anonymousGroup),
                                                      isNull(), eq(embargoDate), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(authorizeService, never()).createOrModifyPolicy(any(), any(), any(), same(uwUsersGroup),
                                                               any(), any(), eq(Constants.READ),
                                                               any(), any());
        verify(resourcePolicyService).update(any(), same(anonymousPolicy));
    }

    @Test
    public void delayReleaseCreatesOnlyEmbargoedAnonymousPolicy()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(365);
        stubAuthorizedGroups(anonymousGroup, uwUsersGroup);
        ResourcePolicy anonymousPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(anonymousGroup, embargoDate, anonymousPolicy);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.parseTerms(null, null, DELAY_1_YEAR);
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

    @Test
    public void restrictToUwWithoutAnonymousStillCreatesUwPolicy()
        throws SQLException, AuthorizeException {
        LocalDate embargoDate = LocalDate.now().plusDays(1800);
        stubAuthorizedGroups(uwUsersGroup);
        ResourcePolicy uwPolicy = mock(ResourcePolicy.class);
        stubCreatePolicy(uwUsersGroup, null, uwPolicy);

        try (MockedStatic<EPersonServiceFactory> factory = mockGroupService()) {
            embargoSetter.parseTerms(null, null, RESTRICT_5_YEARS);
            embargoSetter.generatePolicies(null, embargoDate, "reason", dso, owningCollection);
        }

        verify(authorizeService, never()).createOrModifyPolicy(any(), any(), any(), same(anonymousGroup),
                                                               any(), any(), eq(Constants.READ),
                                                               any(), any());
        verify(authorizeService).createOrModifyPolicy(isNull(), any(), isNull(), same(uwUsersGroup),
                                                      isNull(), isNull(), eq(Constants.READ),
                                                      eq("reason"), same(dso));
        verify(resourcePolicyService).update(any(), same(uwPolicy));
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

    private void stubCreatePolicy(Group group, LocalDate embargoDate, ResourcePolicy policy)
        throws SQLException, AuthorizeException {
        when(authorizeService.createOrModifyPolicy(isNull(), any(), isNull(), same(group), isNull(),
                                                   embargoDate == null ? isNull() : eq(embargoDate),
                                                   eq(Constants.READ), any(), same(dso)))
            .thenReturn(policy);
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
}
