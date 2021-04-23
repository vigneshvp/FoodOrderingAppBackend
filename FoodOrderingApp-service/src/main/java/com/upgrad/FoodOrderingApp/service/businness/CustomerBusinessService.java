package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerAuthEntityDao;
import com.upgrad.FoodOrderingApp.service.dao.CustomerEntityDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class CustomerBusinessService {

    private static final String EMAIL_FORMAT = "^[A-Za-z0-9]+@(.+)$";
    private static final String PASSWORD_FORMAT = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[#@$%&*!^])(?=\\\\S+$).{8,20}$";
    private final CustomerEntityDao customerEntityDao;
    private final CustomerAuthEntityDao customerAuthEntityDao;
    private final PasswordCryptographyProvider passwordCryptographyProvider;

    @Autowired
    public CustomerBusinessService(final CustomerEntityDao customerEntityDao, final CustomerAuthEntityDao customerAuthEntityDao, final PasswordCryptographyProvider passwordCryptographyProvider) {
        this.customerEntityDao = customerEntityDao;
        this.customerAuthEntityDao = customerAuthEntityDao;
        this.passwordCryptographyProvider = passwordCryptographyProvider;
    }

    /**
     * Creates a customer
     *
     * @param customerEntity
     * @return the created customer
     * @throws SignUpRestrictedException
     */
    @Transactional
    public CustomerEntity createCustomer(final CustomerEntity customerEntity) throws SignUpRestrictedException {
        String password = customerEntity.getPassword();
        CustomerEntity existingCustomerEntity;
        existingCustomerEntity = customerEntityDao.getCustomerByContactNumber(customerEntity.getContactNumber());
        if (existingCustomerEntity != null) {
            throw new SignUpRestrictedException("SGR-001",
                    "This contact number is already registered! Try other contact number.");
        }
        if (!validateCustomerEntity(customerEntity)) {
            throw new SignUpRestrictedException("SGR-005",
                    "Except last name all fields should be filled");
        }
        if (!validateEmail(customerEntity.getEmail())) {
            throw new SignUpRestrictedException("SGR-002",
                    "Invalid email-id format!");
        }
        if (!validateContactNumber(customerEntity.getContactNumber())) {
            throw new SignUpRestrictedException("SGR-003",
                    "Invalid contact number!");
        }
        if (!validatePassword(customerEntity.getPassword())) {
            throw new SignUpRestrictedException("SGR-004",
                    "Weak password!");
        }
        //Encrypt the password
        String[] encryptedText = passwordCryptographyProvider.encrypt(customerEntity.getPassword());
        customerEntity.setSalt(encryptedText[0]);
        customerEntity.setPassword(encryptedText[1]);
        return customerEntityDao.createCustomer(customerEntity);

    }

    /**
     * Login for a customer
     *
     * @param authorization
     * @return CustomerAuthEntity with login details
     * @throws AuthenticationFailedException
     */
    @Transactional
    public CustomerAuthEntity login(final String authorization)
            throws AuthenticationFailedException {
        String base64EncodedCredentials = authorization.split("Basic ")[1];
        if (base64EncodedCredentials == null || StringUtils.isEmpty(base64EncodedCredentials)) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
        byte[] decode = Base64.getDecoder().decode(base64EncodedCredentials);
        String decodedText = new String(decode);
        String[] decodedArray = decodedText.split(":");
        String contactNumber = decodedArray[0];
        String password = decodedArray[1];
        if (password == null || StringUtils.isEmpty(password) || contactNumber == null || StringUtils.isEmpty(contactNumber)) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
        CustomerEntity customerEntity = customerEntityDao.getCustomerByContactNumber(contactNumber);
        if (customerEntity == null) {
            throw new AuthenticationFailedException("ATH-001", "This contact number has not been registered!");
        }

        final String encryptedPassword = PasswordCryptographyProvider
                .encrypt(password, customerEntity.getSalt());
        if (encryptedPassword.equals(customerEntity.getPassword())) {
            JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(encryptedPassword);
            CustomerAuthEntity customerAuthToken = new CustomerAuthEntity();
            customerAuthToken.setCustomer(customerEntity);
            final ZonedDateTime now = ZonedDateTime.now();
            final ZonedDateTime expiresAt = now.plusHours(8);
            customerAuthToken.setAccessToken(
                    jwtTokenProvider.generateToken(customerEntity.getUuid(), now, expiresAt));
            customerAuthToken.setLoginAt(now);
            customerAuthToken.setExpiresAt(expiresAt);
            customerAuthToken.setUuid(UUID.randomUUID().toString());
            customerEntityDao.createAuthToken(customerAuthToken);
            return customerAuthToken;
        } else {
            throw new AuthenticationFailedException("ATH-002", "Invalid Credentials");
        }

    }


    /**
     * Logout a customer
     *
     * @param accessToken
     * @return The CustomerAuthEntity
     * @throws AuthorizationFailedException
     */
    @Transactional
    public CustomerAuthEntity logout(final String accessToken) throws AuthorizationFailedException {
        CustomerAuthEntity customerAuthEntity = customerEntityDao.getCustomerAuthToken(accessToken);
        if (customerAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in");
        }
        final ZonedDateTime now = ZonedDateTime.now();
        if (customerAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }
        if (customerAuthEntity.getExpiresAt().compareTo(now) <= 0) {
            throw new AuthorizationFailedException("ATHR-003", "Your session is expired. Log in again to access this endpoint.");
        }
        customerAuthEntity.setLogoutAt(now);
        customerEntityDao.updateCustomerAuthEntity(customerAuthEntity);
        return customerAuthEntity;
    }


    /**
     * This method updates the details of a customer
     *
     * @param accessToken
     * @param customerEntity
     * @return the updated customer entity
     * @throws AuthorizationFailedException
     * @throws UpdateCustomerException
     */
    @Transactional
    public CustomerEntity update(final String accessToken, final CustomerEntity customerEntity) throws AuthorizationFailedException, UpdateCustomerException {
        CustomerAuthEntity customerAuthEntity = customerEntityDao.getCustomerAuthToken(accessToken);
        if (customerAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in");
        }
        final ZonedDateTime now = ZonedDateTime.now();
        if (customerAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }
        if (customerAuthEntity.getExpiresAt().compareTo(now) <= 0) {
            throw new AuthorizationFailedException("ATHR-003", "Your session is expired. Log in again to access this endpoint.");
        }
        if (customerEntity.getFirstName() == null || StringUtils.isEmpty(customerEntity.getFirstName())) {
            throw new UpdateCustomerException("UCR-002", "First name field should not be empty");
        }
        CustomerEntity updatedCustomerEntity = customerAuthEntity.getCustomer();
        updatedCustomerEntity.setFirstName(customerEntity.getFirstName());
        updatedCustomerEntity.setLastName(customerEntity.getLastName());
        customerEntityDao.updateCustomer(updatedCustomerEntity);
        return updatedCustomerEntity;
    }

    /**
     * This method updates a password for a customer
     *
     * @param accessToken
     * @param oldPassword
     * @param newPassword
     * @return the updated customer entity with new password
     * @throws AuthorizationFailedException
     * @throws UpdateCustomerException
     * @throws SignUpRestrictedException
     */
    @Transactional
    public CustomerEntity updatePassword(final String accessToken, final String oldPassword, final String newPassword) throws AuthorizationFailedException, UpdateCustomerException, SignUpRestrictedException {
        if (oldPassword == null || StringUtils.isEmpty(oldPassword) || newPassword == null || StringUtils.isEmpty(newPassword)) {
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        }
        CustomerAuthEntity customerAuthEntity = customerEntityDao.getCustomerAuthToken(accessToken);
        if (customerAuthEntity == null) {
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in");
        }
        final ZonedDateTime now = ZonedDateTime.now();
        if (customerAuthEntity.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }
        if (customerAuthEntity.getExpiresAt().compareTo(now) <= 0) {
            throw new AuthorizationFailedException("ATHR-003", "Your session is expired. Log in again to access this endpoint.");
        }
        CustomerEntity customerEntity = customerAuthEntity.getCustomer();
        String[] encryptedText = passwordCryptographyProvider.encrypt(oldPassword);
        // If encrypted password stored in database and encrypted password from request do not match , throw exception
        if (!StringUtils.equals(encryptedText[1], oldPassword)) {
            throw new UpdateCustomerException("UCR-004", "Incorrect old password");
        }
        if (!validatePassword(newPassword)) {
            throw new UpdateCustomerException("UCR-001", "Weak password!");
        }
        String[] encryptedTextForNewPassword = passwordCryptographyProvider.encrypt(newPassword);
        customerEntity.setPassword(encryptedTextForNewPassword[1]);
        customerEntity.setSalt(encryptedTextForNewPassword[0]);
        customerEntityDao.updateCustomer(customerEntity);
        return customerEntity;
    }


    /**
     * Validates a customer entity object
     *
     * @param customerEntity
     * @return false when any field other than last name is empty
     */
    private boolean validateCustomerEntity(CustomerEntity customerEntity) {
        if (Objects.isNull(customerEntity.getFirstName()) || StringUtils.isEmpty(customerEntity.getFirstName())) {
            return false;
        } else if (Objects.isNull(customerEntity.getEmail()) || StringUtils.isEmpty(customerEntity.getEmail())) {
            return false;
        } else if (Objects.isNull(customerEntity.getPassword()) || StringUtils.isEmpty(customerEntity.getPassword())) {
            return false;
        } else
            return !Objects.isNull(customerEntity.getContactNumber()) && !StringUtils.isEmpty(customerEntity.getContactNumber());
    }

    private boolean validateEmail(String email) {
        Pattern pattern = Pattern.compile(EMAIL_FORMAT);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    private boolean validateContactNumber(String contactNumber) {
        if (contactNumber.length() != 10)
            return false;
        return Pattern.matches("\\d", contactNumber);
    }

    private boolean validatePassword(String password) {
        if (password.length() < 8)
            return false;
        Pattern pattern = Pattern.compile(PASSWORD_FORMAT);
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }

}

