package repeating_key_xor

import "testing"

func TestEncrypt(t *testing.T) {
	type args struct {
		s   string
		key string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test encrypt run successfully",
			args: args{
				s:   "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
				key: "ICE",
			},
			want:    "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
			wantErr: false,
		},
		{
			name: "Test encrypt run successfully on empty input",
			args: args{
				s:   "",
				key: "ICE",
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "Test encrypt run successfully on empty key",
			args: args{
				s:   "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
				key: "",
			},
			want:    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encrypt(tt.args.s, tt.args.key)
			if got != tt.want {
				t.Errorf("Encrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}
