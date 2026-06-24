import {
  Injectable,
  NotFoundException,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserProfileDto, PublicUserProfileDto } from './dto/user-profile.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { LoginResponseDto } from './dto/login.dto';
import { UserRole } from '@prisma/client';
import { RegisterResponseDto } from './dto/register-response.dto';

import { randomBytes, createHash } from 'crypto';

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Get authenticated user's full profile
   */
  async getMyProfile(walletAddress: string): Promise<UserProfileDto> {
    const user = await this.prisma.user.findFirst({
      where: { walletAddress, deletedAt: null },
      include: {
        campaigns: {
          where: { status: 'ACTIVE' },
        },
        donations: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Calculate stats
    const totalRaised = user.campaigns.reduce(
      (sum, campaign) => sum + parseFloat(campaign.raisedAmount.toString()),
      0,
    );

    const totalDonated = user.donations.reduce(
      (sum, donation) => sum + parseFloat(donation.amount.toString()),
      0,
    );

    return {
      id: user.id,
      email: user.email,
      displayName: user.displayName || undefined,
      name: user.name || undefined,
      phone: user.phone || undefined,
      bio: user.bio || undefined,
      avatarUrl: user.avatarUrl || undefined,
      role: user.role,
      kycStatus: user.kycStatus,
      emailVerifiedAt: user.emailVerifiedAt || undefined,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      deletedAt: user.deletedAt || undefined,
      totalRaised,
      totalDonated,
      campaignCount: user.campaigns.length,
    };
  }

  /**
   * Update authenticated user's profile
   */
  async updateMyProfile(
    walletAddress: string,
    updateDto: UpdateUserDto,
  ): Promise<UserProfileDto> {
    const user = await this.prisma.user.findFirst({
      where: { walletAddress, deletedAt: null },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // If email is being changed, ensure it's not already in use
    if (updateDto.email && updateDto.email !== user.email) {
      const existing = await this.prisma.user.findUnique({
        where: { email: updateDto.email },
      });
      if (existing) {
        throw new BadRequestException('Email already in use');
      }
    }

    // Parse preferences JSON if provided
    let parsedPreferences = user.preferences;
    if (updateDto.preferences) {
      try {
        parsedPreferences = JSON.parse(updateDto.preferences);
      } catch {
        throw new BadRequestException('Invalid preferences JSON');
      }
    }

    const updated = await this.prisma.user.update({
      where: { id: user.id },
      data: {
        email: updateDto.email ?? user.email,
        name: updateDto.name ?? user.name,
        phone: updateDto.phone ?? user.phone,
        preferences: parsedPreferences,
        displayName: updateDto.displayName ?? user.displayName,
        bio: updateDto.bio ?? user.bio,
        avatarUrl: updateDto.avatarUrl ?? user.avatarUrl,
        socialLinks: (updateDto.socialLinks ?? user.socialLinks) as any,
      },
      include: {
        campaigns: {
          where: { status: 'ACTIVE' },
        },
        donations: true,
      },
    });

    const totalRaised = updated.campaigns.reduce(
      (sum, campaign) => sum + parseFloat(campaign.raisedAmount.toString()),
      0,
    );

    const totalDonated = updated.donations.reduce(
      (sum, donation) => sum + parseFloat(donation.amount.toString()),
      0,
    );

    return {
      id: updated.id,
      email: updated.email,
      displayName: updated.displayName || undefined,
      name: updated.name || undefined,
      phone: updated.phone || undefined,
      bio: updated.bio || undefined,
      avatarUrl: updated.avatarUrl || undefined,
      role: updated.role,
      kycStatus: updated.kycStatus,
      emailVerifiedAt: updated.emailVerifiedAt || undefined,
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
      deletedAt: updated.deletedAt || undefined,
      totalRaised,
      totalDonated,
      campaignCount: updated.campaigns.length,
    };
  }

  /**
   * Get public profile for a user by wallet address
   */
  async getPublicProfile(
    walletAddress: string,
  ): Promise<PublicUserProfileDto> {
    const user = await this.prisma.user.findFirst({
      where: { walletAddress, deletedAt: null },
      include: {
        campaigns: {
          where: { status: 'ACTIVE' },
        },
      },
    });

    if (!user) {
      throw new NotFoundException(
        `User with wallet address ${walletAddress} not found`,
      );
    }

    const totalRaised = user.campaigns.reduce(
      (sum, campaign) => sum + parseFloat(campaign.raisedAmount.toString()),
      0,
    );

    return {
      displayName: user.displayName || undefined,
      avatarUrl: user.avatarUrl || undefined,
      bio: user.bio || undefined,
      verifiedStatus: user.kycStatus === 'VERIFIED',
      campaignCount: user.campaigns.length,
      totalRaised,
    };
  }

  /**
   * Update KYC status for a user (admin only)
   */
  async updateKYCStatus(
    userId: string,
    status: 'VERIFIED' | 'REJECTED' | 'PENDING',
    adminId: string,
  ): Promise<{ success: boolean; message: string }> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { kycStatus: status },
    });

    await this.prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'ADMIN_ACTION',
        resourceType: 'User',
        resourceId: userId,
        details: JSON.stringify({
          action: 'KYC_STATUS_UPDATE',
          previousStatus: user.kycStatus,
          newStatus: status,
        }),
      },
    });

    return {
      success: true,
      message: `User KYC status updated to ${status}`,
    };
  }

  /**
   * Login with email + password, returning JWT access and refresh tokens.
   */
  async login(email: string, password: string): Promise<LoginResponseDto> {
    const maxAttempts = this.config.get<number>('LOGIN_MAX_ATTEMPTS', 5);
    const lockoutSeconds = this.config.get<number>(
      'LOGIN_LOCKOUT_SECONDS',
      900,
    );

    const user = await this.prisma.user.findFirst({
      where: { email, deletedAt: null },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const retryAfter = Math.ceil(
        (user.lockedUntil.getTime() - Date.now()) / 1000,
      );
      throw new UnauthorizedException(
        `Account locked. Try again in ${retryAfter}s`,
      );
    }

    if (!user.passwordHash) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const valid = await bcrypt.compare(password, user.passwordHash);

    if (!valid) {
      const attempts = user.loginAttempts + 1;
      const lockedUntil =
        attempts >= maxAttempts
          ? new Date(Date.now() + lockoutSeconds * 1000)
          : null;

      await this.prisma.user.update({
        where: { id: user.id },
        data: { loginAttempts: attempts, lockedUntil },
      });

      throw new UnauthorizedException('Invalid credentials');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { loginAttempts: 0, lockedUntil: null },
    });

    const payload = { sub: user.id, email: user.email, role: user.role };

    const accessToken = this.jwt.sign(payload, {
      secret: this.config.get<string>('JWT_SECRET', 'default-secret'),
      expiresIn: '15m',
    });

    const refreshToken = this.jwt.sign(
      { sub: user.id },
      {
        secret: this.config.get<string>(
          'REFRESH_TOKEN_SECRET',
          'default-refresh-secret',
        ),
        expiresIn: '7d',
      },
    );

    return { accessToken, refreshToken, tokenType: 'Bearer' };
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private generateConfirmationToken(): string {
    // Keep it reasonably long so it matches ConfirmEmailDto @MinLength(16)
    return randomBytes(24).toString('hex');
  }

  /**
   * POST /users/register
   */
  async register(
    email: string,
    walletAddress: string,
    password: string,
  ): Promise<RegisterResponseDto> {
    const existingEmail = await this.prisma.user.findUnique({
      where: { email },
    });
    if (existingEmail) {
      throw new BadRequestException('Email already in use');
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        walletAddress,
        email,
        passwordHash,
        role: 'USER',
      },
    });

    const token = this.generateConfirmationToken();
    const tokenHash = this.hashToken(token);

    // 24h default
    const expiresHours = this.config.get<number>('EMAIL_TOKEN_EXPIRES_HOURS', 24);
    const expiresAt = new Date(Date.now() + expiresHours * 60 * 60 * 1000);

    await this.prisma.emailVerificationToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
      },
    });

    // Email sending not implemented in this repo yet.
    // For now, we return a message (and token could be logged by caller in dev).
    return {
      message: 'Registration successful. Please confirm your email.',
    };
  }

  /**
   * POST /users/confirm-email
   */
  async confirmEmail(token: string): Promise<RegisterResponseDto> {
    if (!token) {
      throw new BadRequestException('Token is required');
    }

    const tokenHash = this.hashToken(token);

    const verification = await this.prisma.emailVerificationToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!verification || !verification.user) {
      throw new BadRequestException('Invalid or expired token');
    }

    if (verification.usedAt) {
      throw new BadRequestException('Token already used');
    }

    if (verification.expiresAt <= new Date()) {
      throw new BadRequestException('Invalid or expired token');
    }

    await this.prisma.$transaction([
      this.prisma.emailVerificationToken.update({
        where: { tokenHash },
        data: { usedAt: new Date() },
      }),
      this.prisma.user.update({
        where: { id: verification.userId },
        data: { emailVerifiedAt: new Date() },
      }),
    ]);

    return { message: 'Email confirmed successfully.' };
  }

  /**
   * Get or create user by wallet address
   */
  async getOrCreateUser(email: string) {
    let user = await this.prisma.user.findFirst({
      where: { email, deletedAt: null },
    });

    if (!user) {
      user = await this.prisma.user.create({
        data: {
          email,
          role: 'DONOR',
        },
      });

      await this.prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'USER_CREATED',
          resourceType: 'User',
          resourceId: user.id,
          details: JSON.stringify({ email }),
        },
      });
    }

    return user;
  }

  /**
   * Update user role (admin only)
   */
  async updateUserRole(
    userId: string,
    role: UserRole,
    adminId: string,
  ): Promise<{ success: boolean; message: string }> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Update role
    await this.prisma.user.update({
      where: { id: userId },
      data: { role },
    });

    // Log to AuditLog
    await this.prisma.auditLog.create({
      data: {
        userId: adminId,
        action: 'ADMIN_ACTION',
        resourceType: 'User',
        resourceId: userId,
        details: JSON.stringify({
          action: 'ROLE_UPDATE',
          previousRole: user.role,
          newRole: role,
        }),
      },
    });

    return {
      success: true,
      message: `User role updated to ${role}`,
    };
  }
}

