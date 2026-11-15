package io.floci.aws.services.iam;

import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.testing.PartnerPermissionBoundaryProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The long-term half of temporary delegation: the partner guide says long-term permissions "limit
 * the permissions of any roles that are created or managed through temporary access" and are
 * "implemented as IAM permissions boundaries", registered for the partner out of band, by email,
 * with no API at all.
 *
 * <p>So the boundaries come from configuration here, keyed by the partner account AWS registered
 * them for, and the chain is the one AWS describes: a request a registered partner files reports
 * the boundaries on itself, which is where {@code RolePermissionRestrictionArns} comes from on AWS
 * rather than from any input, the credentials exchanged for that request's token carry them, and a
 * role created with those credentials is bounded by one. Without a registration nothing carries
 * anything, which is the partner that never onboarded.
 */
@QuarkusTest
@TestProfile(PartnerPermissionBoundaryProfile.class)
class DelegationRoleBoundaryIntegrationTest {

    private static final String CUSTOMER = "222233334444";
    private static final String PARTNER = "000000000001";
    private static final String UNREGISTERED_PARTNER = "000000000002";
    private static final String TOPIC = "arn:aws:sns:us-east-1:000000000001:partner-notifications";
    private static final String TEMPLATE = "arn:aws:iam::partner:policy/template/example";
    private static final String BOUNDARY =
            "arn:aws:iam::partner:policy/permission_boundary/example.com/ReadOnlyAccess_20261101";
    private static final String TRUST = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
              "Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}""";

    @Inject
    DelegationRequestService delegationRequests;

    @Inject
    IamService iamService;

    @Test
    void aRequestFiledByARegisteredPartnerReportsTheBoundariesRegisteredForIt() {
        String id = partnerCreate(PARTNER);

        assertEquals(List.of(BOUNDARY), RequestScopes.callAs(CUSTOMER,
                () -> delegationRequests.get(CUSTOMER, id).getRolePermissionRestrictionArns()));
    }

    @Test
    void aRequestFiledByAPartnerWithNoRegistrationReportsNone() {
        String id = partnerCreate(UNREGISTERED_PARTNER);

        assertEquals(List.of(), RequestScopes.callAs(CUSTOMER,
                () -> delegationRequests.get(CUSTOMER, id).getRolePermissionRestrictionArns()));
    }

    @Test
    void aRoleCreatedWithDelegatedCredentialsCarriesTheRegisteredBoundary() {
        String id = approved(partnerCreate(PARTNER));
        String[] credentials = delegatedCredentials(PARTNER, id);

        // The session is where the cap travels: the request named it and the exchange carried it.
        assertEquals(Optional.of(BOUNDARY), RequestScopes.callAs(CUSTOMER,
                () -> iamService.delegatedRoleBoundaryArn(credentials[0])));

        given().header("Authorization", sessionAuth(credentials[0]))
                .header("X-Amz-Security-Token", credentials[2])
                .formParam("Action", "CreateRole")
                .formParam("Version", "2010-05-08")
                .formParam("RoleName", "delegated-" + UUID.randomUUID().toString().substring(0, 8))
                .formParam("AssumeRolePolicyDocument", TRUST)
            .when().post("/").then().statusCode(200)
                .body("CreateRoleResponse.CreateRoleResult.Role.PermissionsBoundary"
                        + ".PermissionsBoundaryArn", equalTo(BOUNDARY));
    }

    @Test
    void aRoleCreatedByAnyoneElseCarriesOnlyTheBoundaryTheCallAsksFor() {
        given().header("Authorization", auth(CUSTOMER, "iam"))
                .formParam("Action", "CreateRole")
                .formParam("Version", "2010-05-08")
                .formParam("RoleName", "undelegated-" + UUID.randomUUID().toString().substring(0, 8))
                .formParam("AssumeRolePolicyDocument", TRUST)
            .when().post("/").then().statusCode(200)
                .body(not(containsString("PermissionsBoundary")));
    }

    private String approved(String id) {
        byCustomer("AssociateDelegationRequest", id);
        byCustomer("AcceptDelegationRequest", id);
        byCustomer("SendDelegationToken", id);
        return id;
    }

    /** The access key, secret and session token the partner gets for the released token. */
    private String[] delegatedCredentials(String partnerAccountId, String id) {
        String token = RequestScopes.callAs(CUSTOMER,
                () -> delegationRequests.get(CUSTOMER, id).getExchangeToken());
        ExtractableResponse<Response> exchanged = given()
                .header("Authorization", auth(partnerAccountId, "sts"))
                .formParam("Action", "GetDelegatedAccessToken")
                .formParam("Version", "2011-06-15")
                .formParam("TradeInToken", token)
            .when().post("/").then().statusCode(200).extract();
        String result = "GetDelegatedAccessTokenResponse.GetDelegatedAccessTokenResult.Credentials.";
        return new String[] {
            exchanged.path(result + "AccessKeyId"),
            exchanged.path(result + "SecretAccessKey"),
            exchanged.path(result + "SessionToken"),
        };
    }

    private static String partnerCreate(String partnerAccountId) {
        return given().header("Authorization", auth(partnerAccountId, "iam"))
                .formParam("Action", "CreateDelegationRequest")
                .formParam("Version", "2010-05-08")
                .formParam("Description", "Set up the integration")
                .formParam("NotificationChannel", TOPIC)
                .formParam("RequestorWorkflowId", "workflow-" + Long.toString(System.nanoTime(), 36))
                .formParam("SessionDuration", "3600")
                .formParam("OwnerAccountId", CUSTOMER)
                .formParam("Permissions.PolicyTemplateArn", TEMPLATE)
            .when().post("/").then().statusCode(200)
                .extract().path("CreateDelegationRequestResponse.CreateDelegationRequestResult"
                        + ".DelegationRequestId");
    }

    private static void byCustomer(String action, String id) {
        given().header("Authorization", auth(CUSTOMER, "iam"))
                .formParam("Action", action)
                .formParam("Version", "2010-05-08")
                .formParam("DelegationRequestId", id)
            .when().post("/").then().statusCode(200);
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20261002/us-east-1/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static String sessionAuth(String accessKeyId) {
        return auth(accessKeyId, "iam");
    }
}
