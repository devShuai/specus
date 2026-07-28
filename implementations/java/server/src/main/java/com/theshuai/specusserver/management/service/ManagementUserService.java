package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.model.ManagementUserView;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@Service
public class ManagementUserService {
    private final ManagementUserRepository repository;
    private final AuthProperties authProperties;

    public ManagementUserService(ManagementUserRepository repository,
                                 AuthProperties authProperties) {
        this.repository = repository;
        this.authProperties = authProperties;
    }

    @Transactional(readOnly = true)
    public Optional<LoginUser> authenticate(String username, String password) {
        if (!StringUtils.hasText(username) || password == null) {
            return Optional.empty();
        }
        String normalized = normalizeUsername(username);
        if (normalized.equalsIgnoreCase(authProperties.getUsername())) {
            if (!isAdminPasswordLoginEnabled() || !constantTimeEquals(authProperties.getPassword(), password)) {
                return Optional.empty();
            }
            return Optional.of(new LoginUser(
                    authProperties.getUsername(),
                    TenantContext.normalize(authProperties.getTenantId()),
                    ManagementRole.ADMIN,
                    true));
        }
        return repository.findByUsernameIgnoreCase(normalized)
                .filter(ManagementUser::isEnabled)
                .filter(user -> PasswordService.matches(password, user.getPasswordHash()))
                .map(user -> new LoginUser(user.getUsername(), user.getTenantId(), user.getRole(), false));
    }

    @Transactional(readOnly = true)
    public ManagementUserView currentUser(ManagementContext context) {
        if (context.username().equalsIgnoreCase(authProperties.getUsername())) {
            String now = Instant.now().toString();
            return new ManagementUserView(
                    authProperties.getUsername(),
                    context.tenant().tenantId(),
                    ManagementRole.ADMIN,
                    true,
                    true,
                    true,
                    now,
                    now);
        }
        return repository.findByUsernameIgnoreCase(context.username())
                .map(this::toView)
                .orElse(new ManagementUserView(
                        context.username(),
                        context.tenant().tenantId(),
                        context.isAdmin() ? ManagementRole.ADMIN : ManagementRole.USER,
                        context.isAdmin(),
                        false,
                        true,
                        null,
                        null));
    }

    @Transactional(readOnly = true)
    public List<ManagementUserView> listUsers(ManagementContext context) {
        requireAdmin(context);
        List<ManagementUserView> views = new ArrayList<>();
        String now = Instant.now().toString();
        views.add(new ManagementUserView(
                authProperties.getUsername(),
                context.tenant().tenantId(),
                ManagementRole.ADMIN,
                true,
                true,
                true,
                now,
                now));
        repository.findByTenantIdOrderByUsernameAsc(context.tenant().tenantId()).stream()
                .map(this::toView)
                .forEach(views::add);
        return views.stream()
                .sorted(Comparator.comparing(ManagementUserView::builtIn).reversed()
                        .thenComparing(ManagementUserView::username, String.CASE_INSENSITIVE_ORDER))
                .toList();
    }

    LoginUser registerVerifiedUser(String rawUsername, String passwordHash) {
        String username = normalizeUsername(rawUsername);
        if (isReservedUsername(username)) {
            throw new IllegalArgumentException("该用户名不可用");
        }
        if (repository.existsByUsernameIgnoreCase(username)) {
            throw new IllegalArgumentException("用户名已存在: " + username);
        }
        if (!StringUtils.hasText(passwordHash) || !passwordHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("密码摘要无效");
        }
        String tenantId = TenantContext.normalize(authProperties.getTenantId());
        String now = Instant.now().toString();
        ManagementUser user = new ManagementUser();
        user.setUsername(username);
        user.setTenantId(tenantId);
        user.setPasswordHash(passwordHash);
        user.setRole(ManagementRole.USER);
        user.setEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        ManagementUser saved = repository.save(user);
        return new LoginUser(saved.getUsername(), saved.getTenantId(), saved.getRole(), false);
    }

    boolean isReservedUsername(String username) {
        return StringUtils.hasText(username) && username.trim().equalsIgnoreCase(authProperties.getUsername());
    }

    @Transactional
    public ManagementUserView createUser(ManagementContext context, UserMutation request) {
        requireAdmin(context);
        String username = normalizeUsername(request.username());
        if (username.equalsIgnoreCase(authProperties.getUsername())) {
            throw new IllegalArgumentException("内置 admin 用户不能重复创建");
        }
        if (repository.existsByUsernameIgnoreCase(username)) {
            throw new IllegalArgumentException("用户名已存在: " + username);
        }
        String password = requirePassword(request.password());
        String now = Instant.now().toString();
        ManagementUser user = new ManagementUser();
        user.setUsername(username);
        user.setTenantId(context.tenant().tenantId());
        user.setPasswordHash(PasswordService.hash(password));
        user.setRole(request.role() == null ? ManagementRole.USER : request.role());
        user.setEnabled(request.enabled() == null || request.enabled());
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return toView(repository.save(user));
    }

    @Transactional
    public ManagementUserView updateUser(ManagementContext context, String username, UserMutation request) {
        requireAdmin(context);
        String normalized = normalizeUsername(username);
        if (normalized.equalsIgnoreCase(authProperties.getUsername())) {
            throw new IllegalArgumentException("内置 admin 用户只能通过配置文件修改");
        }
        ManagementUser user = repository.findByUsernameIgnoreCase(normalized)
                .orElseThrow(() -> new IllegalArgumentException("用户不存在: " + normalized));
        if (StringUtils.hasText(request.password())) {
            user.setPasswordHash(PasswordService.hash(request.password().trim()));
        }
        if (request.role() != null) {
            user.setRole(request.role());
        }
        if (request.enabled() != null) {
            user.setEnabled(request.enabled());
        }
        user.setUpdatedAt(Instant.now().toString());
        return toView(repository.save(user));
    }

    @Transactional
    public void deleteUser(ManagementContext context, String username) {
        requireAdmin(context);
        String normalized = normalizeUsername(username);
        if (normalized.equalsIgnoreCase(authProperties.getUsername())) {
            throw new IllegalArgumentException("内置 admin 用户不能删除");
        }
        ManagementUser user = repository.findByUsernameIgnoreCase(normalized)
                .orElseThrow(() -> new IllegalArgumentException("用户不存在: " + normalized));
        repository.delete(user);
    }

    public void requireAdmin(ManagementContext context) {
        if (context == null || !context.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "需要 admin 权限");
        }
    }

    private boolean isAdminPasswordLoginEnabled() {
        return authProperties.isPasswordLoginEnabled() && StringUtils.hasText(authProperties.getPassword());
    }

    private ManagementUserView toView(ManagementUser user) {
        boolean admin = user.getRole() == ManagementRole.ADMIN;
        return new ManagementUserView(
                user.getUsername(),
                TenantContext.normalize(user.getTenantId()),
                user.getRole(),
                admin,
                false,
                user.isEnabled(),
                user.getCreatedAt(),
                user.getUpdatedAt());
    }

    String normalizeUsername(String username) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("username cannot be blank");
        }
        String normalized = username.trim();
        if (normalized.length() > 80) {
            throw new IllegalArgumentException("username is too long");
        }
        return normalized;
    }

    String requirePassword(String password) {
        if (!StringUtils.hasText(password)) {
            throw new IllegalArgumentException("password cannot be blank");
        }
        String normalized = password.trim();
        if (normalized.length() > 120) {
            throw new IllegalArgumentException("password is too long");
        }
        return normalized;
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                actual.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public record LoginUser(String username, String tenantId, ManagementRole role, boolean builtInAdmin) {
    }

    public record UserMutation(String username, String password, ManagementRole role, Boolean enabled) {
    }
}
