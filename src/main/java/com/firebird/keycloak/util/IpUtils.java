package com.firebird.keycloak.util;

import com.firebird.keycloak.IpAddressAuthenticator;
import org.jboss.logging.Logger;

import java.net.*;

/**
 * @author Sergei Klimovich
 */
public class IpUtils {
    private static final Logger logger = Logger.getLogger(IpUtils.class);
    /**
     * Проверяет, находится ли IP в разрешённом диапазоне.
     *
     * @param clientIp   IP-адрес клиента.
     * @param allowedIps Строка с разрешёнными IP или подсетями, разделёнными запятой.
     * @return true, если клиентский IP разрешён, иначе false.
     */
    public static boolean isIpAllowed(String clientIp, String allowedIps) {
        String[] allowedEntries = allowedIps.split(",");
        for (String entry : allowedEntries) {
            String trimmedEntry = entry.trim();
            if (trimmedEntry.contains("/")) {
                // Это подсеть
                if (isIpInSubnet(clientIp, trimmedEntry)) {
                    return true;
                }
            } else {
                // Это одиночный IP
                if (clientIp.equals(trimmedEntry)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Проверяет, находится ли IP-адрес в указанной подсети.
     *
     * @param clientIp IP-адрес клиента.
     * @param subnet   Подсеть в формате CIDR (например, 192.168.1.0/24).
     * @return true, если IP находится в подсети, иначе false.
     */
    private static boolean isIpInSubnet(String clientIp, String subnet) {
        try {
            String[] parts = subnet.split("/");
            String subnetIp = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);

            InetAddress clientAddress = InetAddress.getByName(clientIp);
            InetAddress subnetAddress = InetAddress.getByName(subnetIp);

            byte[] clientBytes = clientAddress.getAddress();
            byte[] subnetBytes = subnetAddress.getAddress();

            if (clientBytes.length != subnetBytes.length) {
                return false; // IPv4 и IPv6 не совместимы
            }

            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            // Проверка полных байт
            for (int i = 0; i < fullBytes; i++) {
                if (clientBytes[i] != subnetBytes[i]) {
                    return false;
                }
            }

            // Проверка оставшихся битов
            if (remainingBits > 0) {
                int mask = 0xFF00 >> remainingBits & 0xFF;
                return (clientBytes[fullBytes] & mask) == (subnetBytes[fullBytes] & mask);
            }

            return true;
        } catch (UnknownHostException | NumberFormatException e) {
            logger.infof("###### CIDR format is invalid: %s", clientIp);
            return false;
        }
    }
}
