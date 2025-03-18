package userservice.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import userservice.model.User;

import java.security.Key;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private static final String secretKey = "SRPSKDSPFf32SDLRLFV<KVfmvjfvnaoslmfooijfurfurjnfhhadgvcfbcbgefq2234mkffdfdfsadsdefedfvxxsadw245678899890956893hfbhf";
    private static final long jwtExpiration = 86400000;
    private static final long refreshExpiration = 604800000;

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);

    }
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(User user){
        Map<String, Object> claims = new HashMap<>();
        claims.put("firstname", user.getFirstname());
        claims.put("roles", user.getRole().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        return generateToken(claims, user, jwtExpiration);
    }
    public String generateToken(Map<String, Object> claims, User user, long expiration){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(User user){
        return buildToken(new HashMap<>(), user, refreshExpiration);
    }

    private String buildToken(Map<String,Object> extraClaims, User user,long expiration){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(user.getEmail())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
    // Проверка наличия ролей в токене
    public boolean containsRoles(String token){
        Claims claims = extractAllClaims(token);
        return claims.containsKey("roles");
    }

    public List<String> extractRoles(String token){
        Claims claims = extractAllClaims(token);
        Object rolesObject = claims.get("roles");

        if (rolesObject instanceof List){
            return ((List<?>) rolesObject).stream()
                    .map(role -> {
                        if (role instanceof LinkedHashMap){
                            Object roleName = ((LinkedHashMap<?,?>)role).get("name");
                            if (roleName != null){
                                return roleName.toString();
                            }else {
                                throw new RuntimeException("Role name is missing or null");
                            }
                        }else {
                                return role.toString();
                            }
                    })
                    .collect(Collectors.toList());
        }
        throw new IllegalArgumentException("Invalid roles format in token");
    }

    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
