/*
 * Copyright (c) 2018 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.api.idpmgt;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.ProvisioningConnectorConfig;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static org.wso2.carbon.identity.api.idpmgt.IdPConstants.*;
import static org.wso2.carbon.identity.api.idpmgt.IdPUtils.*;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.*;

/*
 * This class contains the mapping between Identity Provider Manager and Rest API interface
 */
public class IDPMgtBridgeService {

    private static final Log log = LogFactory.getLog(IdentityProviderManager.class);

    private IdentityProviderManager identityProviderManager = IdentityProviderManager.getInstance();

    private static IDPMgtBridgeService instance = new IDPMgtBridgeService();

    private IdPConfigParser idPConfigParser;

    private static final int DEFAULT_SEARCH_LIMIT = 100;

    private IDPMgtBridgeService() {

        idPConfigParser = new IdPConfigParser();
    }

    public static IDPMgtBridgeService getInstance() {

        return instance;
    }

    /**
     * Delete an existing IDP.
     *
     * @param idpName Identity Provider name.
     * @throws IDPMgtBridgeServiceException IDPMgtBridgeServiceException.
     */
    public void deleteIDP(String idpName) throws IDPMgtBridgeServiceException {

        String tenantDomain = getTenantDomain();
        try {
            if (isDefaultIDP(idpName)) {
                throw handleClientException(ErrorMessages.ERROR_CODE_FAIL_RESIDENT_IDP_DELETE, null);
            }
            IdentityProvider identityProvider = getIDPByName(idpName, tenantDomain);
            identityProviderManager.deleteIdP(identityProvider.getIdentityProviderName(), tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw handleServerException(ErrorMessages.ERROR_CODE_INTERNAL_ERROR, null, e);
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("Identity provider: %s is deleted successfully", idpName));
        }
    }

    private String getTenantDomain() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    /**
     * Add an IDP.
     *
     * @param identityProvider Identity Provider which needs to be added.
     * @return The identity provider which was added.
     * @throws IDPMgtBridgeServiceException IDPMgtBridgeServiceException.
     */
    public IdentityProvider addIDP(IdentityProvider identityProvider) throws IDPMgtBridgeServiceException {

        String tenantDomain = getTenantDomain();
        try {
            validateAddRequest(identityProvider, tenantDomain);
            identityProviderManager.addIdP(identityProvider, tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Identity provider: %s is added successfully", identityProvider
                        .getIdentityProviderName()));
            }
            return identityProviderManager.getIdPByName(identityProvider.getIdentityProviderName(), tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw handleServerException(ErrorMessages.ERROR_CODE_INTERNAL_ERROR, null, e);
        }
    }

    /**
     * Returns IdentityProvider instance which is corresponding to the given name.
     *
     * @param idpName name of the identity provider
     * @return Identity Provider with givne name
     * @throws IDPMgtBridgeServiceException IDPMgtBridgeServiceException.
     */
    public IdentityProvider getIDPByName(String idpName) throws IDPMgtBridgeServiceException {

        return getIDPByName(idpName, getTenantDomain());
    }

    private IdentityProvider getIDPByName(String idpName, String tenantDomain) throws IDPMgtBridgeServiceException {

        IdentityProvider idp;
        try {
            idp = identityProviderManager.getIdPByName(idpName, tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw handleServerException(ErrorMessages.ERROR_CODE_INTERNAL_ERROR, null, e);
        }
        if (idp == null || StringUtils.isEmpty(idp.getId())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_RESOURCE_NOT_FOUND, null);
        }

        return idp;
    }

    /**
     * Function returns the set of authenticators for a given IDP
     *
     * @param idpName name of the idp
     * @param limit   limit of the query
     * @param offset  starting index of the query
     * @return list of authenticators which satisfy the query parameters
     * @throws IDPMgtBridgeServiceException throws
     */
    public List<FederatedAuthenticatorConfig> getAuthenticatorList(String idpName, Integer limit, Integer offset) throws
            IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(idpName, getTenantDomain());

        if (ArrayUtils.isNotEmpty(idp.getFederatedAuthenticatorConfigs())) {
            List<FederatedAuthenticatorConfig> federatedAuthenticatorConfigs = Arrays.asList(idp
                    .getFederatedAuthenticatorConfigs());

            federatedAuthenticatorConfigs.sort(Comparator.comparing(FederatedAuthenticatorConfig::getName));
            return (List<FederatedAuthenticatorConfig>) paginationList(federatedAuthenticatorConfigs, limit, offset);
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Function returns the authenticator detail for a given IDP
     *
     * @param idpName  name of the idp
     * @param authName name of the authenticator
     * @return list of authenticators which satisfy the query parameters
     * @throws IDPMgtBridgeServiceException throws
     */
    public List<FederatedAuthenticatorConfig> getAuthenticatorByName(String idpName, String authName)
            throws
            IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(idpName, getTenantDomain());

        if (ArrayUtils.isNotEmpty(idp.getFederatedAuthenticatorConfigs())) {
            List<FederatedAuthenticatorConfig> federatedAuthenticatorConfigs = Arrays.asList(idp
                    .getFederatedAuthenticatorConfigs());
            Optional<FederatedAuthenticatorConfig> optionalFederatedAuthenticatorConfig = federatedAuthenticatorConfigs
                    .stream().filter
                            (federatedAuthenticatorConfig ->
                                    federatedAuthenticatorConfig.getName().equals(authName)).findFirst();
            if (optionalFederatedAuthenticatorConfig.isPresent()) {
                ArrayList<FederatedAuthenticatorConfig> federatedAuthenticatorConfigs1 = new ArrayList<>();
                federatedAuthenticatorConfigs1.add(optionalFederatedAuthenticatorConfig.get());
                return federatedAuthenticatorConfigs1;
            }
            return Collections.emptyList();
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Function returns the set of provision connectors for a given IDP
     *
     * @param idpID  name of the idp
     * @param limit  limit of the query
     * @param offset starting index of the query
     * @return list of authenticators which satisfy the query parameters
     * @throws IDPMgtBridgeServiceException throws IDPMgtBridgeServiceException
     */
    public List<ProvisioningConnectorConfig> getOutboundConnectorList(String idpID, Integer limit, Integer offset)
            throws IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(idpID, getTenantDomain());

        if (ArrayUtils.isNotEmpty(idp.getProvisioningConnectorConfigs())) {
            List<ProvisioningConnectorConfig> provisioningConnectorConfigs = Arrays.asList(idp
                    .getProvisioningConnectorConfigs());
            provisioningConnectorConfigs.sort(Comparator.comparing(ProvisioningConnectorConfig::getName));
            return (List<ProvisioningConnectorConfig>) paginationList(provisioningConnectorConfigs, limit, offset);
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Function returns the set of provision connectors for a given IDP
     *
     * @param idpID         name of the idp
     * @param connectorName connector name
     * @return list of authenticators which satisfy the query parameters
     * @throws IDPMgtBridgeServiceException throws IDPMgtBridgeServiceException
     */
    public List<ProvisioningConnectorConfig> getOutboundConnectorByName(String idpID, String connectorName)
            throws IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(idpID, getTenantDomain());

        if (ArrayUtils.isNotEmpty(idp.getProvisioningConnectorConfigs())) {
            List<ProvisioningConnectorConfig> provisioningConnectorConfigs = Arrays.asList(idp
                    .getProvisioningConnectorConfigs());

            Optional<ProvisioningConnectorConfig> optionalProvisioningConnectorConfig = provisioningConnectorConfigs
                    .stream().filter
                            (provisioningConnectorConfig ->
                                    provisioningConnectorConfig.getName().equals(connectorName)).findFirst();
            if (optionalProvisioningConnectorConfig.isPresent()) {
                ArrayList<ProvisioningConnectorConfig> provisioningConnectorConfigArrayList = new ArrayList<>();
                provisioningConnectorConfigArrayList.add(optionalProvisioningConnectorConfig.get());
                return provisioningConnectorConfigArrayList;
            }
        }
        return Collections.emptyList();
    }

    /**
     * Function returns the set of provision connectors for a given IDP
     *
     * @param idpName       name of the idp
     * @param connectorName connector name
     * @throws IDPMgtBridgeServiceException throws IDPMgtBridgeServiceException
     */
    public void deleteOutboundConnector(String idpName, String connectorName) throws IDPMgtBridgeServiceException {

        if (connectorName == null) {
            throw handleClientException(ErrorMessages.ERROR_CODE_NULL_CONNECTOR, null);
        }
        IdentityProvider idp = getIDPByName(idpName, getTenantDomain());

        if (ArrayUtils.isNotEmpty(idp.getProvisioningConnectorConfigs())) {
            List<ProvisioningConnectorConfig> provisioningConnectorConfigs = Arrays.asList(idp
                    .getProvisioningConnectorConfigs());

            ArrayList<ProvisioningConnectorConfig> updatedList = new ArrayList<>(provisioningConnectorConfigs);
            boolean hasConnector = false;
            for (int i = 0; i < updatedList.size(); ++i) {
                if (updatedList.get(i).getName().equals(connectorName)) {
                    updatedList.remove(i);

                    hasConnector = true;
                }
            }
            if (!hasConnector) {
                throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_CONNECTOR_DELETE, null);
            }

            idp.setProvisioningConnectorConfigs(updatedList.toArray(new ProvisioningConnectorConfig[0]));
            updateIDP(idp, idpName);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Deleted Outbound connector: %s from IDP: %s", connectorName
                        , idp.getIdentityProviderName()));
            }
        } else {
            throw handleClientException(ErrorMessages.ERROR_CODE_NULL_CONNECTOR_LIST, null);
        }
    }

    /**
     * Get the existing list of identity providers in the system.
     *
     * @return List of existing Identity Providers in the system as Identity Providers.
     * @throws IDPMgtBridgeServiceException IDPMgtBridgeServiceServerException.
     */
    public List<IdentityProvider> getIDPs(Integer limit, Integer offset) throws IDPMgtBridgeServiceException {

        List<IdentityProvider> identityProviders;
        try {
            String tenantDomain = getTenantDomain();
            identityProviders = identityProviderManager.getIdPs(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw handleServerException(ErrorMessages.ERROR_CODE_INTERNAL_ERROR, null, e);
        }
        identityProviders.sort(Comparator.comparing(IdentityProvider::getIdentityProviderName));
        return (List<IdentityProvider>) paginationList(identityProviders, limit, offset);
    }

    private int getDefaultLimitFromConfig() {

        int limit = DEFAULT_SEARCH_LIMIT;

        if (idPConfigParser.getConfiguration().get(IDP_SEARCH_LIMIT_PATH) != null) {
            limit = Integer.parseInt(idPConfigParser.getConfiguration()
                    .get(IDP_SEARCH_LIMIT_PATH).toString());
        }
        return limit;
    }

    private List<?> paginationList(List<?> list, Integer limit, Integer offset) throws
            IDPMgtBridgeServiceClientException {

        if (limit == null) {
            limit = getDefaultLimitFromConfig();
        }

        if (offset == null) {
            offset = 0;
        }

        validatePaginationParameters(limit, offset);

        int endIndex;
        if (list.size() <= (limit + offset)) {
            endIndex = list.size();
        } else {
            endIndex = (limit + offset);
        }
        if (list.size() < offset) {
            endIndex = 0;
            offset = 0;
        }
        return list.subList(offset, endIndex);
    }

    /**
     * Updates an existing IDP.
     *
     * @param identityProvider Identity Provider which needs to be updated.
     * @param name             Identity Provider name.
     * @return Updated Identity Provider.
     * @throws IDPMgtBridgeServiceException IDPMgtBridgeServiceClientException.
     */
    public IdentityProvider updateIDP(IdentityProvider identityProvider, String name) throws
            IDPMgtBridgeServiceException {

        String tenantDomain = getTenantDomain();
        try {
            IdentityProvider oldIDP = getIDPByName(name, tenantDomain);
            validateUpdateRequest(identityProvider, oldIDP, tenantDomain);
            identityProviderManager.updateIdP(oldIDP.getIdentityProviderName(), identityProvider, tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Identity provider: %s is updated successfully", identityProvider
                        .getIdentityProviderName()));
            }
            return identityProviderManager.getIdPByName(identityProvider.getIdentityProviderName(), tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw handleServerException(ErrorMessages.ERROR_CODE_INTERNAL_ERROR, null, e);
        }
    }

    /**
     * Update autheticator
     *
     * @param federatedAuthenticatorConfig federated authenticator that needs to be added
     * @param authName                     name of the authenticator
     * @param name                         name of the IDP
     * @return Updated Identity Provider.
     * @throws IDPMgtBridgeServiceException       throws an IDPMgtBridgeServiceException exception
     * @throws IDPMgtBridgeServiceClientException throws an IDPMgtBridgeServiceClientException exception
     */
    public IdentityProvider updateAuthenticator(FederatedAuthenticatorConfig federatedAuthenticatorConfig, String
            authName, String name) throws IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(name, getTenantDomain());
        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = idp.getFederatedAuthenticatorConfigs();
        if (federatedAuthenticatorConfigs == null) {
            federatedAuthenticatorConfigs = new ArrayList<FederatedAuthenticatorConfig>().toArray(new
                    FederatedAuthenticatorConfig[0]);
        }
        List<FederatedAuthenticatorConfig> federatedAuthenticatorConfigsAsList = Arrays.asList
                (federatedAuthenticatorConfigs);
        ArrayList<FederatedAuthenticatorConfig> updatedList = new ArrayList<>(federatedAuthenticatorConfigsAsList);
        validateUpdateRequest(federatedAuthenticatorConfig, updatedList, authName);

        idp.setFederatedAuthenticatorConfigs(updatedList.toArray(new FederatedAuthenticatorConfig[0]));
        idp = updateIDP(idp, name);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Authentication: %s is added to IDP: %s", federatedAuthenticatorConfig
                    .getDisplayName(), idp.getIdentityProviderName()));
        }
        return idp;
    }

    private void validateUpdateRequest(FederatedAuthenticatorConfig federatedAuthenticatorConfig,
                                       List<FederatedAuthenticatorConfig> federatedAuthenticatorConfigList,
                                       String authName) throws IDPMgtBridgeServiceClientException {

        if (federatedAuthenticatorConfig == null) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_TYPE_RECIEVED, null);
        }

        if (StringUtils.isEmpty(federatedAuthenticatorConfig.getName())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_FEDERATED_CONFIG, null);
        }

        Optional<FederatedAuthenticatorConfig> optionalFederatedAuthenticatorConfig = federatedAuthenticatorConfigList
                .stream().filter(federatedAuthenticatorConfigObject ->
                        federatedAuthenticatorConfigObject.getName().equals(authName)).findFirst();
        if (!optionalFederatedAuthenticatorConfig.isPresent()) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_AUTHENTICATOR, null);
        }
        federatedAuthenticatorConfigList.remove(optionalFederatedAuthenticatorConfig.get());

        Optional<FederatedAuthenticatorConfig> optionalFederatedAuthenticatorConfigArrayList =
                federatedAuthenticatorConfigList
                .stream().filter(federatedAuthenticatorConfigObject ->
                        federatedAuthenticatorConfigObject.getName().equals(federatedAuthenticatorConfig.getName())).findFirst();
        if (optionalFederatedAuthenticatorConfigArrayList.isPresent()) {
            throw handleClientException(ErrorMessages.ERROR_CODE_EXIST_AUTHENTICATOR, null);
        }

        federatedAuthenticatorConfigList.add(federatedAuthenticatorConfig);
    }

    /**
     * Update claim configuration
     *
     * @param receivedClaimConfig claim configuration that needs to be added
     * @param name                name of the IDP
     * @return Updated Identity Provider.
     * @throws IDPMgtBridgeServiceException       throws an IDPMgtBridgeServiceException exception
     * @throws IDPMgtBridgeServiceClientException throws an IDPMgtBridgeServiceClientException exception
     */
    public IdentityProvider updateClaimConfiguration(ClaimConfig receivedClaimConfig, String name) throws
            IDPMgtBridgeServiceException {

        validateClaimConfig(receivedClaimConfig);
        IdentityProvider idp = getIDPByName(name, getTenantDomain());
        idp.setClaimConfig(receivedClaimConfig);
        idp = updateIDP(idp, name);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Claim: %s is added to IDP: %s", receivedClaimConfig
                    .getUserClaimURI(), idp.getIdentityProviderName()));
        }

        return idp;
    }

    private void validateClaimConfig(ClaimConfig receivedClaimConfig) throws IDPMgtBridgeServiceClientException {

        if (receivedClaimConfig == null) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_TYPE_RECIEVED, null);
        }
    }

    /**
     * Update role
     *
     * @param permissionsAndRoleConfig role configuration that needs to be added
     * @param name                     name of the IDP
     * @return Updated Identity Provider.
     * @throws IDPMgtBridgeServiceException       throws an IDPMgtBridgeServiceException exception
     * @throws IDPMgtBridgeServiceClientException throws an IDPMgtBridgeServiceClientException exception
     */
    public IdentityProvider updateRoles(PermissionsAndRoleConfig permissionsAndRoleConfig, String name) throws
            IDPMgtBridgeServiceException {

        validateRoles(permissionsAndRoleConfig);
        IdentityProvider idp = getIDPByName(name, getTenantDomain());
        idp.setPermissionAndRoleConfig(permissionsAndRoleConfig);
        idp = updateIDP(idp, name);

        if (log.isDebugEnabled()) {
            log.debug(String.format("New permission set is added to IDP: %s", idp.getIdentityProviderName()));
        }

        return idp;
    }

    private void validateRoles(PermissionsAndRoleConfig permissionsAndRoleConfig) throws
            IDPMgtBridgeServiceClientException {

        if (permissionsAndRoleConfig == null) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_TYPE_RECIEVED, null);
        }

        if (ArrayUtils.isEmpty(permissionsAndRoleConfig.getIdpRoles()) || ArrayUtils.isEmpty(permissionsAndRoleConfig
                .getRoleMappings())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_ROLE_CONFIG, null);
        }
    }

    /**
     * Update jit provisioning configuration
     *
     * @param justInTimeProvisioningConfig JIT provisioning configuration that needs to be added
     * @param name                         name of the IDP
     * @return Updated Identity Provider.
     * @throws IDPMgtBridgeServiceException throws an IDPMgtBridgeServiceException exception
     */
    public IdentityProvider updateJITProvisioningConfig(JustInTimeProvisioningConfig justInTimeProvisioningConfig,
                                                        String name)
            throws
            IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(name, getTenantDomain());
        idp.setJustInTimeProvisioningConfig(justInTimeProvisioningConfig);
        idp = updateIDP(idp, name);

        if (log.isDebugEnabled()) {
            log.debug(String.format("New JIT provisioning set: %s is added to IDP: %s", justInTimeProvisioningConfig
                    .getUserStoreClaimUri(), idp.getIdentityProviderName()));
        }

        return idp;
    }

    /**
     * Update an existing provisioning connector
     *
     * @param provisioningConnectorConfig provisioning connector configuration that needs to be added
     * @param connectorName               name of the connector
     * @param name                        name of the IDP
     * @return Updated Identity Provider.
     * @throws IDPMgtBridgeServiceException throws an IDPMgtBridgeServiceException exception
     */
    public IdentityProvider updateProvisioningConnectorConfig(ProvisioningConnectorConfig provisioningConnectorConfig,
                                                              String connectorName,
                                                              String name) throws IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(name, getTenantDomain());
        ProvisioningConnectorConfig[] provisioningConnectorConfigs = idp.getProvisioningConnectorConfigs();
        if (provisioningConnectorConfigs == null) {
            provisioningConnectorConfigs = new ArrayList<ProvisioningConnectorConfig>().toArray(new
                    ProvisioningConnectorConfig[0]);
        }
        List<ProvisioningConnectorConfig> provisioningConnectorConfigsList = Arrays.asList
                (provisioningConnectorConfigs);

        List<ProvisioningConnectorConfig> updatedList = new ArrayList<>(provisioningConnectorConfigsList);
        validateUpdateRequest(provisioningConnectorConfig, updatedList, connectorName);
        idp.setProvisioningConnectorConfigs(updatedList.toArray(new ProvisioningConnectorConfig[0]));
        idp = updateIDP(idp, name);

        if (log.isDebugEnabled()) {
            log.debug(String.format("New provisioning connector: %s is added to IDP: %s",
                    provisioningConnectorConfig.getName(), idp.getIdentityProviderName()));
        }

        return idp;
    }

    /**
     * Add a provisioning connector
     *
     * @param provisioningConnectorConfig provisioning connector configuration that needs to be added
     * @param name                        name of the IDP
     * @return Updated Identity Provider.
     * @throws IDPMgtBridgeServiceException throws an IDPMgtBridgeServiceException exception
     */
    public IdentityProvider addProvisioningConnectorConfig(ProvisioningConnectorConfig provisioningConnectorConfig,
                                                           String name) throws IDPMgtBridgeServiceException {

        IdentityProvider idp = getIDPByName(name, getTenantDomain());
        ProvisioningConnectorConfig[] provisioningConnectorConfigs = idp.getProvisioningConnectorConfigs();
        if (provisioningConnectorConfigs == null) {
            provisioningConnectorConfigs = new ArrayList<ProvisioningConnectorConfig>().toArray(new
                    ProvisioningConnectorConfig[0]);
        }
        List<ProvisioningConnectorConfig> provisioningConnectorConfigsList = Arrays.asList
                (provisioningConnectorConfigs);
        List<ProvisioningConnectorConfig> updatedList = new ArrayList<>(provisioningConnectorConfigsList);

        validateAddRequest(provisioningConnectorConfig, updatedList);
        updatedList.add(provisioningConnectorConfig);
        idp.setProvisioningConnectorConfigs(updatedList.toArray(new
                ProvisioningConnectorConfig[0]));
        idp = updateIDP(idp, name);

        if (log.isDebugEnabled()) {
            log.debug(String.format("New provisioning connector: %s is added to IDP: %s",
                    provisioningConnectorConfig.getName(), idp.getIdentityProviderName()));
        }
        return idp;
    }

    private void validateAddRequest(ProvisioningConnectorConfig provisioningConnectorConfig,
                                    List<ProvisioningConnectorConfig> provisioningConnectorConfigList)
            throws IDPMgtBridgeServiceClientException {

        if (provisioningConnectorConfig == null) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_TYPE_RECIEVED, null);
        }

        if (StringUtils.isEmpty(provisioningConnectorConfig.getName())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_PROVISIONING_CONFIG, null);
        }

        Optional<ProvisioningConnectorConfig> optionalProvisioningConnectorConfig1 = provisioningConnectorConfigList
                .stream().filter(provisioningConnectorConfig1 ->
                        provisioningConnectorConfig1.getName().equals(provisioningConnectorConfig.getName())).findFirst();
        if (optionalProvisioningConnectorConfig1.isPresent()) {
            throw handleClientException(ErrorMessages.ERROR_CODE_EXIST_CONNECTOR, null);
        }
    }

    private void validateUpdateRequest(ProvisioningConnectorConfig provisioningConnectorConfig,
                                       List<ProvisioningConnectorConfig> provisioningConnectorConfigList,
                                       String connectorName) throws IDPMgtBridgeServiceClientException {

        if (provisioningConnectorConfig == null) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_TYPE_RECIEVED, null);
        }

        if (StringUtils.isEmpty(provisioningConnectorConfig.getName())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_PROVISIONING_CONFIG, null);
        }

        Optional<ProvisioningConnectorConfig> optionalProvisioningConnectorConfig = provisioningConnectorConfigList
                .stream().filter(provisioningConnectorConfig1 ->
                        provisioningConnectorConfig1.getName().equals(connectorName)).findFirst();
        if (!optionalProvisioningConnectorConfig.isPresent()) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_CONNECTOR, null);
        }
        provisioningConnectorConfigList.remove(optionalProvisioningConnectorConfig.get());

        Optional<ProvisioningConnectorConfig> optionalProvisioningConnectorConfig1 = provisioningConnectorConfigList
                .stream().filter(provisioningConnectorConfig1 ->
                        provisioningConnectorConfig1.getName().equals(provisioningConnectorConfig.getName())).findFirst();
        if (optionalProvisioningConnectorConfig1.isPresent()) {
            throw handleClientException(ErrorMessages.ERROR_CODE_EXIST_CONNECTOR, null);
        }
        provisioningConnectorConfigList.add(provisioningConnectorConfig);
    }

    private void validateAddRequest(IdentityProvider identityProvider, String tenantDomain) throws
            IDPMgtBridgeServiceClientException, IdentityProviderManagementException {

        String idpName = identityProvider.getIdentityProviderName();
        if (StringUtils.isEmpty(idpName)) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_IDP, null);
        } else if (isDefaultIDP(idpName)) {
            throw handleClientException(ErrorMessages.ERROR_CODE_FAIL_RESIDENT_IDP_ADD, null);
        }
        IdentityProvider oldIDP = identityProviderManager.getIdPByName(idpName, tenantDomain);
        if (oldIDP != null && hasSameIDPName(idpName, oldIDP.getIdentityProviderName())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_IDP_ALREADY_EXIST, null);
        }
    }

    private void validateUpdateRequest(IdentityProvider newIdp, IdentityProvider oldIdp, String tenantDomain) throws
            IDPMgtBridgeServiceException {

        if (StringUtils.isEmpty(newIdp.getIdentityProviderName())) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_IDP, null);
        } else if (StringUtils.equals(oldIdp.getIdentityProviderName(), DEFAULT_IDP_CONFIG) && !StringUtils.equals
                (newIdp.getIdentityProviderName(), DEFAULT_IDP_CONFIG)) {
            throw handleClientException(ErrorMessages.ERROR_CODE_FAIL_RESIDENT_IDP_EDIT, null);
        }
        validateDuplicateIDPs(newIdp, tenantDomain, oldIdp);
    }

    private void validateDuplicateIDPs(IdentityProvider identityProvider, String tenantDomain, IdentityProvider
            oldIDP) throws IDPMgtBridgeServiceException {

        if (!hasSameIDPName(identityProvider.getIdentityProviderName(), oldIDP.getIdentityProviderName())) {
            IdentityProvider duplicateIDP = getIDPByName(identityProvider.getIdentityProviderName(), tenantDomain);
            if (hasSameIDPName(duplicateIDP.getIdentityProviderName(), identityProvider
                    .getIdentityProviderName()) && !StringUtils.equals(identityProvider.getId(), duplicateIDP.getId())) {
                throw handleClientException(ErrorMessages.ERROR_CODE_IDP_ALREADY_EXIST, null);
            }
        }
    }

    private boolean hasSameIDPName(String idpName, String oldIDPName) {

        return StringUtils.equals(idpName, oldIDPName);
    }

    private boolean isDefaultIDP(String idpName) {

        return StringUtils.equals(DEFAULT_IDP_CONFIG, idpName);
    }

    private void validatePaginationParameters(int limit, int offset) throws IDPMgtBridgeServiceClientException {

        if (limit < 0 || offset < 0) {
            throw handleClientException(ErrorMessages.ERROR_CODE_INVALID_ARGS_FOR_LIMIT_OFFSET, null);
        }
    }
}
