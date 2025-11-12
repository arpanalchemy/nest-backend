import { Injectable, Logger } from '@nestjs/common';
import { CognitoService } from 'alchemy-utilities';
import {
  SignUpDto,
  ConfirmSignUpDto,
  LoginDto,
  VerifyMFADto,
  ForgotPasswordDto,
  ConfirmForgotPasswordDto,
  RefreshTokenDto,
  SetupMFADto,
  ConfirmMFADto,
  ChangePasswordDto,
  UpdateUserDto,
} from './dto/auth.dto';

/**
 * Authentication Service
 * 
 * High-level authentication service that wraps CognitoService
 * and provides business logic for authentication flows.
 * 
 * Features:
 * - User registration and email verification
 * - Login with MFA support
 * - Password reset and management
 * - Token refresh and validation
 * - MFA setup and verification
 * - User profile management
 * 
 * @example
 * ```typescript
 * constructor(private authService: AuthService) {}
 * 
 * async register(dto: SignUpDto) {
 *   return await this.authService.signUp(dto);
 * }
 * ```
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly cognitoService: CognitoService) {}

  // ============================================================================
  // AUTHENTICATION
  // ============================================================================

  /**
   * Register a new user
   * @param dto - Sign up data transfer object
   * @returns Registration result with user ID
   */
  async signUp(dto: SignUpDto) {
    this.logger.log(`User registration initiated: ${this.maskEmail(dto.email)}`);
    
    const result = await this.cognitoService.signUp(
      dto.email,
      dto.password,
      dto.attributes,
    );

    return {
      success: true,
      message: result.confirmed 
        ? 'User registered and confirmed successfully' 
        : 'User registered. Please check your email for verification code.',
      data: {
        userId: result.userId,
        confirmed: result.confirmed,
        emailSent: !result.confirmed,
      },
    };
  }

  /**
   * Confirm user email with verification code
   * @param dto - Confirmation data transfer object
   * @returns Confirmation result
   */
  async confirmSignUp(dto: ConfirmSignUpDto) {
    this.logger.log(`Email confirmation initiated: ${this.maskEmail(dto.email)}`);
    
    const result = await this.cognitoService.confirmSignUp(dto.email, dto.code);

    return {
      success: true,
      message: 'Email verified successfully. You can now log in.',
      data: result,
    };
  }

  /**
   * User login
   * @param dto - Login data transfer object
   * @returns Login result with tokens or challenge
   */
  async login(dto: LoginDto): Promise<{
    success: boolean;
    message: string;
    data?: any;
    challenge?: string;
  }> {
    this.logger.log(`Login attempt: ${this.maskEmail(dto.email)}`);
    
    const result = await this.cognitoService.login(dto.email, dto.password);

    // Handle MFA challenge
    if ('requiresMFA' in result) {
      this.logger.log(`MFA challenge required: ${this.maskEmail(dto.email)}`);
      return {
        success: false,
        message: 'MFA verification required',
        challenge: 'MFA',
        data: {
          challengeType: result.challenge,
          session: result.session,
        },
      };
    }

    // Handle new password required
    if ('requiresNewPassword' in result) {
      this.logger.log(`Password change required: ${this.maskEmail(dto.email)}`);
      return {
        success: false,
        message: 'New password required',
        challenge: 'NEW_PASSWORD_REQUIRED',
        data: {
          session: result.session,
        },
      };
    }

    // Successful login
    this.logger.log(`User logged in successfully: ${this.maskEmail(dto.email)}`);
    return {
      success: true,
      message: 'Login successful',
      data: {
        accessToken: result.accessToken,
        idToken: result.idToken,
        refreshToken: result.refreshToken,
        expiresIn: result.expiresIn,
        tokenType: result.tokenType || 'Bearer',
      },
    };
  }

  /**
   * Verify MFA code and complete login
   * @param dto - MFA verification data transfer object
   * @returns Login result with tokens
   */
  async verifyMFA(dto: VerifyMFADto) {
    this.logger.log(`MFA verification: ${this.maskEmail(dto.email)}`);
    
    const result = await this.cognitoService.verifyMFA(
      dto.email,
      dto.session,
      dto.code,
      dto.challengeType,
    );

    return {
      success: true,
      message: 'MFA verified successfully',
      data: {
        accessToken: result.accessToken,
        idToken: result.idToken,
        refreshToken: result.refreshToken,
        expiresIn: result.expiresIn,
        tokenType: result.tokenType || 'Bearer',
      },
    };
  }

  /**
   * Refresh access token
   * @param dto - Refresh token data transfer object
   * @returns New tokens
   */
  async refreshToken(dto: RefreshTokenDto) {
    this.logger.log('Token refresh requested');
    
    const result = await this.cognitoService.refreshToken(dto.refreshToken);

    return {
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: result.accessToken,
        idToken: result.idToken,
        expiresIn: result.expiresIn,
        tokenType: result.tokenType || 'Bearer',
      },
    };
  }

  /**
   * Global sign out
   * @param accessToken - Valid access token
   * @returns Sign out result
   */
  async logout(accessToken: string) {
    this.logger.log('User logout initiated');
    
    const result = await this.cognitoService.globalSignOut(accessToken);

    return {
      success: true,
      message: 'Logged out successfully',
      data: result,
    };
  }

  // ============================================================================
  // PASSWORD MANAGEMENT
  // ============================================================================

  /**
   * Initiate forgot password flow
   * @param dto - Forgot password data transfer object
   * @returns Password reset result
   */
  async forgotPassword(dto: ForgotPasswordDto) {
    this.logger.log(`Password reset requested: ${this.maskEmail(dto.email)}`);
    
    const result = await this.cognitoService.forgotPassword(dto.email);

    return {
      success: true,
      message: 'Password reset code sent to your email',
      data: {
        destination: result.codeDelivery?.Destination,
      },
    };
  }

  /**
   * Confirm forgot password with code
   * @param dto - Confirm forgot password data transfer object
   * @returns Password reset confirmation
   */
  async confirmForgotPassword(dto: ConfirmForgotPasswordDto) {
    this.logger.log(`Password reset confirmation: ${this.maskEmail(dto.email)}`);
    
    const result = await this.cognitoService.confirmForgotPassword(
      dto.email,
      dto.code,
      dto.newPassword,
    );

    return {
      success: true,
      message: 'Password reset successfully',
      data: result,
    };
  }

  /**
   * Change user password (admin operation)
   * @param dto - Change password data transfer object
   * @returns Password change result
   */
  async changePassword(dto: ChangePasswordDto) {
    this.logger.log(`Password change: ${this.maskEmail(dto.email)}`);
    
    const result = await this.cognitoService.setPassword(
      dto.email,
      dto.newPassword,
      dto.permanent,
    );

    return {
      success: true,
      message: 'Password changed successfully',
      data: result,
    };
  }

  // ============================================================================
  // MFA MANAGEMENT
  // ============================================================================

  /**
   * Setup MFA for user
   * @param dto - Setup MFA data transfer object
   * @returns MFA setup result with QR code secret
   */
  async setupMFA(dto: SetupMFADto) {
    this.logger.log('MFA setup initiated');
    
    const result = await this.cognitoService.setupMFA(dto.accessToken);

    return {
      success: true,
      message: 'MFA setup initiated. Scan the QR code with your authenticator app.',
      data: {
        secretCode: result.secretCode,
        qrCodeUrl: this.generateQRCodeUrl(result.secretCode, dto.email),
      },
    };
  }

  /**
   * Confirm MFA setup
   * @param dto - Confirm MFA data transfer object
   * @returns MFA confirmation result
   */
  async confirmMFA(dto: ConfirmMFADto) {
    this.logger.log('MFA confirmation initiated');
    
    const result = await this.cognitoService.confirmMFA(
      dto.accessToken,
      dto.code,
      dto.deviceName,
    );

    return {
      success: true,
      message: 'MFA enabled successfully',
      data: result,
    };
  }

  // ============================================================================
  // USER MANAGEMENT
  // ============================================================================

  /**
   * Get current user details
   * @param accessToken - Valid access token
   * @returns User details
   */
  async getCurrentUser(accessToken: string) {
    this.logger.log('Fetching current user details');
    
    const result = await this.cognitoService.getCurrentUser(accessToken);

    return {
      success: true,
      message: 'User details retrieved successfully',
      data: {
        username: result.username,
        email: result.attributes.email,
        emailVerified: result.attributes.email_verified === 'true',
        attributes: result.attributes,
      },
    };
  }

  /**
   * Update user attributes
   * @param accessToken - Valid access token
   * @param dto - Update user data transfer object
   * @returns Update result
   */
  async updateUser(accessToken: string, dto: UpdateUserDto) {
    this.logger.log('Updating user attributes');
    
    // First get the username from token
    const user = await this.cognitoService.getCurrentUser(accessToken);
    
    const result = await this.cognitoService.updateUserAttributes(
      user.username,
      dto.attributes,
    );

    return {
      success: true,
      message: 'User profile updated successfully',
      data: result,
    };
  }

  /**
   * Verify JWT token
   * @param token - JWT token to verify
   * @returns Verification result with payload
   */
  async verifyToken(token: string) {
    this.logger.log('Token verification requested');
    
    const payload = await this.cognitoService.verifyToken(token);

    return {
      success: true,
      message: 'Token is valid',
      data: {
        userId: payload.sub,
        email: payload.email,
        emailVerified: payload.email_verified,
        username: payload['cognito:username'],
        groups: payload['cognito:groups'] || [],
        exp: payload.exp,
        iat: payload.iat,
      },
    };
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Mask email for logging
   * @param email - Email to mask
   * @returns Masked email
   */
  private maskEmail(email: string): string {
    if (!email || !email.includes('@')) return '***';
    const [local, domain] = email.split('@');
    return `${local.charAt(0)}***@${domain}`;
  }

  /**
   * Generate QR code URL for authenticator apps
   * @param secret - MFA secret code
   * @param email - User email
   * @returns QR code URL
   */
  private generateQRCodeUrl(secret: string, email: string): string {
    const appName = process.env.APP_NAME || 'MyApp';
    const otpAuthUrl = `otpauth://totp/${encodeURIComponent(appName)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(appName)}`;
    return `https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=${encodeURIComponent(otpAuthUrl)}`;
  }

  /**
   * Health check
   * @returns Health status
   */
  async healthCheck() {
    return await this.cognitoService.healthCheck();
  }
}