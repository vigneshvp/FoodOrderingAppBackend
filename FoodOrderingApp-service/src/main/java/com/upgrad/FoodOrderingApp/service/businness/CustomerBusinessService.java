package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerAuthEntityDao;
import com.upgrad.FoodOrderingApp.service.dao.CustomerEntityDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;

import java.util.Base64;
import java.util.UUID;

import javax.transaction.Transactional;
import java.time.ZonedDateTime;
import java.util.Objects;
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

        String[] encryptedText = passwordCryptographyProvider.encrypt(customerEntity.getPassword());
        customerEntity.setSalt(encryptedText[0]);
        customerEntity.setPassword(encryptedText[1]);
        return customerEntityDao.createCustomer(customerEntity);

    }

    @Transactional
    public CustomerAuthEntity login(final String authorization)
            throws AuthenticationFailedException {
        String base64EncodedCredentials = authorization.split("Basic ")[1];
        if(base64EncodedCredentials == null || StringUtils.isEmpty(base64EncodedCredentials)) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
        byte[] decode = Base64.getDecoder().decode(base64EncodedCredentials);
        String decodedText = new String(decode);
        String[] decodedArray = decodedText.split(":");
        String contactNumber = decodedArray[0];
        String password = decodedArray[1];
        if(password == null || StringUtils.isEmpty(password) || contactNumber == null || StringUtils.isEmpty(contactNumber)) {
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

