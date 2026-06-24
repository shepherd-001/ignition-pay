export class UserProfileDto {
  id: string;
  email?: string;
  displayName?: string;
  name?: string;
  phone?: string;
  bio?: string;
  avatarUrl?: string;
  role: string;
  kycStatus: string;
  emailVerifiedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date;

  // Stats
  totalRaised?: number;
  totalDonated?: number;
  campaignCount?: number;
}

export class PublicUserProfileDto {
  displayName?: string;
  avatarUrl?: string;
  bio?: string;
  verifiedStatus: boolean;
  campaignCount: number;
  totalRaised: number;
}
